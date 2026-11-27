#!/usr/bin/env python3
"""Real TCP/IP Protocol Benchmark for NIST Post-Quantum Cryptography (ML-KEM-768 & ML-DSA-65).

Compares:
1. TLS-1.3-style Handshake (ML-KEM-768 Key Exchange + ML-DSA-65 Signature Auth)
2. KEMTLS-style Handshake (ML-KEM-768 Ephemeral + Static KEM Certificate Auth)
3. Proposed RSSI-gated ML-KEM-768 protocol over TCP; RSSI inputs are synthetic.

Supports real Linux kernel network emulation via `tc netem` on loopback (`lo`).
"""

import argparse
import base64
import csv
import hashlib
import hmac
import json
import math
import multiprocessing
import os
import platform
import queue
import socket
import statistics
import struct
import subprocess
import sys
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import oqs
except ImportError as exc:
    raise SystemExit("Missing 'oqs' library. Activate your pqc_env first.") from exc


PROTO_TLS_MLDSA = "TLS13_MLKEM768_MLDSA65"
PROTO_KEMTLS = "KEMTLS_MLKEM768"
PROTOCOLS = (PROTO_TLS_MLDSA, PROTO_KEMTLS)
PROTO_RSSI_GATED = "Proposed_RSSI_Gated_MLKEM768"
RSSI_PROTOCOL_ID = "TK12-MLKEM768-RSSI-1"
DEFAULT_RSSI_BASELINES_DBM = {"alice": -35.0, "bob": -27.0}

HOST = "127.0.0.1"
PORT_TLS = 18443
PORT_KEMTLS = 18444
PORT_RSSI_GATED = 18445

# Realistic X.509 Certificate chain overheads (Root + Intermediate + Leaf metadata)
DEFAULT_MLDSA_CERT_CHAIN_BYTES = 6600
DEFAULT_KEMTLS_CERT_CHAIN_BYTES = 2400

# Network profiles: (Name, Bandwidth_kbit, OneWay_Delay_ms, Jitter_ms)
# Note: tc netem applies delay to egress packets. On loopback (`lo`), each packet
# traverses egress once, so OneWay_Delay_ms = RTT / 2.
NETWORK_PROFILES = [
    {"name": "LAN_100Mbps_2msRTT", "rate_kbit": 100000, "delay_ms": 1.0, "jitter_ms": 0.1},
    {"name": "WAN_10Mbps_40msRTT", "rate_kbit": 10000, "delay_ms": 20.0, "jitter_ms": 2.5},
    {"name": "Constrained_256kbps_300msRTT", "rate_kbit": 256, "delay_ms": 150.0, "jitter_ms": 15.0},
]


# --- Cryptographic Helpers ---
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out = bytearray()
    prev = b""
    counter = 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes((counter,)), hashlib.sha256).digest()
        out.extend(prev)
        counter += 1
    return bytes(out[:length])


def compute_mac(key: bytes, transcript: bytes) -> bytes:
    return hmac.new(key, transcript, hashlib.sha256).digest()


def proposed_canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def proposed_encode_message(value: dict) -> bytes:
    encoded = proposed_canonical_json(value)
    if len(encoded) > 1900:
        raise ValueError("Proposed protocol message exceeds the 802.11 payload limit")
    return encoded


def proposed_decode_message(payload: bytes) -> dict:
    message = json.loads(payload.decode("ascii"))
    if not isinstance(message, dict) or message.get("protocol") != RSSI_PROTOCOL_ID:
        raise ValueError("Invalid proposed-protocol message")
    return message


def proposed_transcript(init_message: dict, response_core: dict) -> bytes:
    init_bytes = proposed_canonical_json(init_message)
    response_bytes = proposed_canonical_json(response_core)
    return len(init_bytes).to_bytes(4, "big") + init_bytes + len(response_bytes).to_bytes(4, "big") + response_bytes


def proposed_session_key(secret_alice_to_bob: bytes, secret_bob_to_alice: bytes, transcript: bytes) -> bytes:
    input_key = secret_alice_to_bob + secret_bob_to_alice
    salt = hashlib.sha256(RSSI_PROTOCOL_ID.encode("ascii") + b"|" + transcript).digest()
    pseudorandom_key = hmac.new(salt, input_key, hashlib.sha256).digest()
    return hmac.new(pseudorandom_key, b"Lan12 transcript key confirmation\x01", hashlib.sha256).digest()


def proposed_mac_hex(key: bytes, label: str, transcript: bytes) -> str:
    return hmac.new(key, label.encode("ascii") + b"|" + transcript, hashlib.sha256).hexdigest()


def proposed_rssi_gate(observed_dbm: float, baseline_dbm: float, tolerance_db: float) -> bool:
    return abs(observed_dbm - baseline_dbm) <= tolerance_db


def proposed_valid_hex_token(value, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def proposed_decode_ciphertext(value: str) -> bytes:
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 1088:
        raise ValueError("Invalid ML-KEM-768 ciphertext length")
    return decoded


# --- TCP Framing Helpers ---
def send_msg(sock: socket.socket, payload: bytes) -> int:
    header = struct.pack("!I", len(payload))
    frame = header + payload
    sock.sendall(frame)
    return len(frame)


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(sock: socket.socket) -> tuple[bytes, int]:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    payload = recv_exact(sock, length)
    return payload, 4 + length


# --- Linux tc netem Network Shaping ---
def apply_tc_netem(rate_kbit: int, delay_ms: float, jitter_ms: float) -> bool:
    """Applies bandwidth and delay shaping to loopback interface `lo`."""
    clear_tc_netem()
    cmd = [
        "sudo", "-n", "tc", "qdisc", "add", "dev", "lo", "root", "netem",
        "delay", f"{delay_ms}ms", f"{jitter_ms}ms", "distribution", "normal",
        "rate", f"{rate_kbit}kbit",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[WARNING] Could not apply tc netem (sudo password required or unsupported kernel): {res.stderr.strip()}")
        return False
    return True


def clear_tc_netem():
    subprocess.run(["sudo", "-n", "tc", "qdisc", "del", "dev", "lo", "root"], capture_output=True)


# --- Server Workers ---
def run_tls_mldsa_server(port: int, cert_bytes_len: int, ready_event: multiprocessing.Event, stop_event: multiprocessing.Event):
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    sig = oqs.Signature("ML-DSA-65")
    server_sig_pk = sig.generate_keypair()
    simulated_cert_chain = os.urandom(cert_bytes_len)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(128)
    srv.settimeout(0.5)
    ready_event.set()

    try:
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with conn:
                try:
                    # Flight 1: Receive ClientHello (ephemeral ML-KEM pk)
                    client_epk, _ = recv_msg(conn)

                    # Server Encapsulate + Sign Transcript
                    ct, shared_secret = kem.encap_secret(client_epk)
                    transcript = client_epk + ct + server_sig_pk + simulated_cert_chain
                    signature = sig.sign(transcript)

                    # Flight 2: Send ServerHello + CT + CertChain + PubKey + Signature
                    flight2 = (
                        struct.pack("!III", len(ct), len(server_sig_pk), len(simulated_cert_chain))
                        + ct
                        + server_sig_pk
                        + simulated_cert_chain
                        + signature
                    )
                    send_msg(conn, flight2)

                    # Derive handshake traffic keys
                    transcript_hash = hashlib.sha256(transcript + signature).digest()
                    hs_secret = hkdf_extract(transcript_hash, shared_secret)
                    c_fin_key = hkdf_expand(hs_secret, b"c_finished")
                    s_fin_key = hkdf_expand(hs_secret, b"s_finished")

                    # Flight 3: Receive Client Finished MAC
                    client_fin, _ = recv_msg(conn)
                    if not hmac.compare_digest(client_fin, compute_mac(c_fin_key, transcript_hash)):
                        raise ValueError("TLS Client Finished MAC mismatch")

                    # Send Server Finished MAC (1-RTT App Data ack)
                    send_msg(conn, compute_mac(s_fin_key, transcript_hash + client_fin))
                except Exception:
                    pass
    finally:
        srv.close()
        kem.free()
        sig.free()


def run_kemtls_server(port: int, cert_bytes_len: int, ready_event: multiprocessing.Event, stop_event: multiprocessing.Event):
    eph_kem = oqs.KeyEncapsulation("ML-KEM-768")
    static_kem = oqs.KeyEncapsulation("ML-KEM-768")
    server_static_pk = static_kem.generate_keypair()
    simulated_cert_chain = os.urandom(cert_bytes_len)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(128)
    srv.settimeout(0.5)
    ready_event.set()

    try:
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with conn:
                try:
                    # Flight 1: Receive ClientHello (ephemeral ML-KEM pk)
                    client_epk, _ = recv_msg(conn)

                    # Server Ephemeral Encapsulate
                    eph_ct, eph_secret = eph_kem.encap_secret(client_epk)

                    # Flight 2: Send ServerHello + Eph_CT + Static_KEM_PK + CertChain
                    flight2 = (
                        struct.pack("!III", len(eph_ct), len(server_static_pk), len(simulated_cert_chain))
                        + eph_ct
                        + server_static_pk
                        + simulated_cert_chain
                    )
                    send_msg(conn, flight2)

                    # Flight 3: Receive Client Static_CT + Client Finished
                    flight3, _ = recv_msg(conn)
                    (static_ct_len,) = struct.unpack("!I", flight3[:4])
                    static_ct = flight3[4 : 4 + static_ct_len]
                    client_fin = flight3[4 + static_ct_len :]

                    # Server Decapsulates Static KEM Secret (Implicit Authentication)
                    static_secret = static_kem.decap_secret(static_ct)

                    transcript = client_epk + eph_ct + server_static_pk + simulated_cert_chain + static_ct
                    transcript_hash = hashlib.sha256(transcript).digest()
                    early_secret = hkdf_extract(transcript_hash, eph_secret)
                    hs_secret = hkdf_extract(early_secret, static_secret)
                    c_fin_key = hkdf_expand(hs_secret, b"kemtls_c_fin")
                    s_fin_key = hkdf_expand(hs_secret, b"kemtls_s_fin")

                    if not hmac.compare_digest(client_fin, compute_mac(c_fin_key, transcript_hash)):
                        raise ValueError("KEMTLS Client Finished MAC mismatch")

                    # Flight 4: Send Server Finished (Mutual Auth Confirmation)
                    send_msg(conn, compute_mac(s_fin_key, transcript_hash + client_fin))
                except Exception:
                    pass
    finally:
        srv.close()
        eph_kem.free()
        static_kem.free()


def run_proposed_rssi_server(
    port: int,
    alice_public_key: bytes,
    alice_fingerprint: str,
    bob_baseline_dbm: float,
    bob_rssi_dbm: float,
    rssi_tolerance_db: float,
    ready_queue: multiprocessing.Queue,
    stop_event: multiprocessing.Event,
):
    bob_kem = oqs.KeyEncapsulation("ML-KEM-768")
    alice_encapsulator = oqs.KeyEncapsulation("ML-KEM-768")
    key_setup_cpu_started = time.process_time_ns()
    key_setup_wall_started = time.perf_counter_ns()
    bob_public_key = bob_kem.generate_keypair()
    bob_fingerprint = hashlib.sha256(bob_public_key).hexdigest()
    bob_key_setup = {
        "cpu_ms": (time.process_time_ns() - key_setup_cpu_started) / 1_000_000,
        "wall_ms": (time.perf_counter_ns() - key_setup_wall_started) / 1_000_000,
    }
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(128)
    server.settimeout(0.5)
    ready_queue.put((bob_public_key, bob_fingerprint, bob_key_setup))
    seen_sessions = set()

    try:
        while not stop_event.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(15)
                try:
                    init_payload, _ = recv_msg(connection)
                    init = proposed_decode_message(init_payload)
                    run_id = init.get("run_id")
                    sequence = init.get("sequence")
                    nonce_a = init.get("nonce_a")
                    if init.get("type") != "INIT":
                        raise ValueError("Expected INIT")
                    if not proposed_valid_hex_token(run_id, 16) or not proposed_valid_hex_token(nonce_a, 32):
                        raise ValueError("Invalid INIT run identifier or nonce")
                    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
                        raise ValueError("Invalid INIT sequence")
                    if init.get("alice_fingerprint") != alice_fingerprint:
                        raise ValueError("Pinned Alice fingerprint mismatch")
                    session_id = (run_id, sequence, nonce_a)
                    if session_id in seen_sessions:
                        raise ValueError("Replayed INIT")
                    seen_sessions.add(session_id)

                    ciphertext_a = proposed_decode_ciphertext(init.get("ciphertext_a", ""))
                    secret_a_bob = bob_kem.decap_secret(ciphertext_a)
                    ciphertext_b, secret_b_bob = alice_encapsulator.encap_secret(alice_public_key)
                    bob_gate = proposed_rssi_gate(
                        bob_rssi_dbm, bob_baseline_dbm, rssi_tolerance_db
                    )
                    nonce_b = secrets.token_hex(16)
                    response_core = {
                        "protocol": RSSI_PROTOCOL_ID,
                        "type": "RESP",
                        "run_id": run_id,
                        "sequence": sequence,
                        "nonce_a": nonce_a,
                        "nonce_b": nonce_b,
                        "bob_fingerprint": bob_fingerprint,
                        "ciphertext_b": base64.b64encode(ciphertext_b).decode("ascii"),
                        "rssi_bob_ok": bob_gate,
                    }
                    transcript = proposed_transcript(init, response_core)
                    bob_session_key = proposed_session_key(
                        secret_a_bob, secret_b_bob, transcript
                    )
                    response = dict(response_core)
                    response["mac_b"] = proposed_mac_hex(
                        bob_session_key, "BOB_RESP", transcript
                    )
                    send_msg(connection, proposed_encode_message(response))

                    finish_payload, _ = recv_msg(connection)
                    finish = proposed_decode_message(finish_payload)
                    finish_core = {key: value for key, value in finish.items() if key != "mac_a"}
                    if (
                        finish_core.get("type") != "FINISH"
                        or finish_core.get("run_id") != run_id
                        or finish_core.get("sequence") != sequence
                        or finish_core.get("nonce_a") != nonce_a
                        or finish_core.get("nonce_b") != nonce_b
                        or not isinstance(finish_core.get("alice_rssi_ok"), bool)
                    ):
                        raise ValueError("Invalid FINISH fields")
                    finish_transcript = transcript + proposed_canonical_json(finish_core)
                    finish_mac_valid = hmac.compare_digest(
                        proposed_mac_hex(bob_session_key, "ALICE_FINISH", finish_transcript),
                        str(finish.get("mac_a", "")).lower(),
                    )
                    accepted = bool(
                        finish_mac_valid and finish_core["alice_rssi_ok"] and bob_gate
                    )
                    acknowledgment = {
                        "protocol": RSSI_PROTOCOL_ID,
                        "type": "ACK",
                        "run_id": run_id,
                        "sequence": sequence,
                        "nonce_a": nonce_a,
                        "accepted": accepted,
                    }
                    ack_transcript = finish_transcript + str(accepted).lower().encode("ascii")
                    acknowledgment["mac_b"] = proposed_mac_hex(
                        bob_session_key, "BOB_ACK", ack_transcript
                    )
                    send_msg(connection, proposed_encode_message(acknowledgment))
                except Exception as error:
                    print(f"Proposed RSSI protocol server error: {error}", file=sys.stderr)
    finally:
        server.close()
        bob_kem.free()
        alice_encapsulator.free()


# --- Client Handshake Benchmarks ---
def client_handshake_tls_mldsa(port: int) -> tuple[float, int]:
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    verifier = oqs.Signature("ML-DSA-65")
    total_bytes = 0

    t_start = time.perf_counter_ns()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        sock.connect((HOST, port))

        # Flight 1: Generate Ephemeral Key & Send ClientHello
        client_epk = kem.generate_keypair()
        total_bytes += send_msg(sock, client_epk)

        # Flight 2: Receive ServerHello + CT + Cert + Signature
        flight2, rx_bytes = recv_msg(sock)
        total_bytes += rx_bytes
        ct_len, pk_len, cert_len = struct.unpack("!III", flight2[:12])
        offset = 12
        ct = flight2[offset : offset + ct_len]
        offset += ct_len
        server_sig_pk = flight2[offset : offset + pk_len]
        offset += pk_len
        cert_chain = flight2[offset : offset + cert_len]
        offset += cert_len
        signature = flight2[offset:]

        # Decapsulate & Verify ML-DSA-65 Signature
        shared_secret = kem.decap_secret(ct)
        transcript = client_epk + ct + server_sig_pk + cert_chain
        if not verifier.verify(transcript, signature, server_sig_pk):
            raise RuntimeError("ML-DSA-65 signature verification failed!")

        transcript_hash = hashlib.sha256(transcript + signature).digest()
        hs_secret = hkdf_extract(transcript_hash, shared_secret)
        c_fin_key = hkdf_expand(hs_secret, b"c_finished")
        s_fin_key = hkdf_expand(hs_secret, b"s_finished")

        # Flight 3: Send Client Finished & Wait for Server Ack
        client_fin = compute_mac(c_fin_key, transcript_hash)
        total_bytes += send_msg(sock, client_fin)

        server_fin, rx_bytes2 = recv_msg(sock)
        total_bytes += rx_bytes2
        if not hmac.compare_digest(server_fin, compute_mac(s_fin_key, transcript_hash + client_fin)):
            raise RuntimeError("Server Finished verification failed!")

        elapsed_ms = (time.perf_counter_ns() - t_start) / 1_000_000
        return elapsed_ms, total_bytes
    finally:
        sock.close()
        kem.free()
        verifier.free()


def client_handshake_kemtls(port: int) -> tuple[float, int]:
    eph_kem = oqs.KeyEncapsulation("ML-KEM-768")
    static_kem = oqs.KeyEncapsulation("ML-KEM-768")
    total_bytes = 0

    t_start = time.perf_counter_ns()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        sock.connect((HOST, port))

        # Flight 1: Generate Ephemeral Key & Send ClientHello
        client_epk = eph_kem.generate_keypair()
        total_bytes += send_msg(sock, client_epk)

        # Flight 2: Receive ServerHello + Eph_CT + Static_PK + CertChain
        flight2, rx_bytes = recv_msg(sock)
        total_bytes += rx_bytes
        ct_len, pk_len, cert_len = struct.unpack("!III", flight2[:12])
        offset = 12
        eph_ct = flight2[offset : offset + ct_len]
        offset += ct_len
        server_static_pk = flight2[offset : offset + pk_len]
        offset += pk_len
        cert_chain = flight2[offset : offset + cert_len]

        # Decapsulate Ephemeral & Encapsulate to Server Static KEM Key
        eph_secret = eph_kem.decap_secret(eph_ct)
        static_ct, static_secret = static_kem.encap_secret(server_static_pk)

        transcript = client_epk + eph_ct + server_static_pk + cert_chain + static_ct
        transcript_hash = hashlib.sha256(transcript).digest()
        early_secret = hkdf_extract(transcript_hash, eph_secret)
        hs_secret = hkdf_extract(early_secret, static_secret)
        c_fin_key = hkdf_expand(hs_secret, b"kemtls_c_fin")
        s_fin_key = hkdf_expand(hs_secret, b"kemtls_s_fin")

        # Flight 3: Send Static_CT + Client Finished
        client_fin = compute_mac(c_fin_key, transcript_hash)
        flight3 = struct.pack("!I", len(static_ct)) + static_ct + client_fin
        total_bytes += send_msg(sock, flight3)

        # Flight 4: Receive Server Finished (Mutual Auth Confirmation)
        server_fin, rx_bytes2 = recv_msg(sock)
        total_bytes += rx_bytes2
        if not hmac.compare_digest(server_fin, compute_mac(s_fin_key, transcript_hash + client_fin)):
            raise RuntimeError("KEMTLS Server Finished verification failed!")

        elapsed_ms = (time.perf_counter_ns() - t_start) / 1_000_000
        return elapsed_ms, total_bytes
    finally:
        sock.close()
        eph_kem.free()
        static_kem.free()


def client_handshake_proposed_rssi(
    port: int,
    alice_kem,
    alice_public_key: bytes,
    alice_fingerprint: str,
    bob_public_key: bytes,
    bob_fingerprint: str,
    sequence: int,
    alice_baseline_dbm: float,
    alice_rssi_dbm: float,
    rssi_tolerance_db: float,
) -> tuple[float, int, bool, bool, bool]:
    total_bytes = 0
    started = time.perf_counter_ns()
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    connection.settimeout(15)
    try:
        connection.connect((HOST, port))
        run_id = secrets.token_hex(8)
        nonce_a = secrets.token_hex(16)
        ciphertext_a, secret_a_alice = alice_kem.encap_secret(bob_public_key)
        init = {
            "protocol": RSSI_PROTOCOL_ID,
            "type": "INIT",
            "run_id": run_id,
            "sequence": sequence,
            "nonce_a": nonce_a,
            "alice_fingerprint": alice_fingerprint,
            "ciphertext_a": base64.b64encode(ciphertext_a).decode("ascii"),
        }
        total_bytes += send_msg(connection, proposed_encode_message(init))

        response_payload, received_bytes = recv_msg(connection)
        total_bytes += received_bytes
        response = proposed_decode_message(response_payload)
        response_core = {key: value for key, value in response.items() if key != "mac_b"}
        if (
            response_core.get("type") != "RESP"
            or response_core.get("run_id") != run_id
            or response_core.get("sequence") != sequence
            or response_core.get("nonce_a") != nonce_a
            or response_core.get("bob_fingerprint") != bob_fingerprint
            or not proposed_valid_hex_token(response_core.get("nonce_b"), 32)
            or not isinstance(response_core.get("rssi_bob_ok"), bool)
        ):
            raise ValueError("Invalid RESP fields or pinned Bob fingerprint")
        ciphertext_b = proposed_decode_ciphertext(response_core.get("ciphertext_b", ""))
        secret_b_alice = alice_kem.decap_secret(ciphertext_b)
        transcript = proposed_transcript(init, response_core)
        alice_session_key = proposed_session_key(
            secret_a_alice, secret_b_alice, transcript
        )
        if not hmac.compare_digest(
            proposed_mac_hex(alice_session_key, "BOB_RESP", transcript),
            str(response.get("mac_b", "")).lower(),
        ):
            raise RuntimeError("Proposed protocol BOB_RESP confirmation failed")

        alice_gate = proposed_rssi_gate(
            alice_rssi_dbm, alice_baseline_dbm, rssi_tolerance_db
        )
        finish_core = {
            "protocol": RSSI_PROTOCOL_ID,
            "type": "FINISH",
            "run_id": run_id,
            "sequence": sequence,
            "nonce_a": nonce_a,
            "nonce_b": response_core["nonce_b"],
            "alice_rssi_ok": alice_gate,
        }
        finish_transcript = transcript + proposed_canonical_json(finish_core)
        finish = dict(finish_core)
        finish["mac_a"] = proposed_mac_hex(
            alice_session_key, "ALICE_FINISH", finish_transcript
        )
        total_bytes += send_msg(connection, proposed_encode_message(finish))

        ack_payload, received_bytes = recv_msg(connection)
        total_bytes += received_bytes
        acknowledgment = proposed_decode_message(ack_payload)
        accepted = acknowledgment.get("accepted")
        if (
            acknowledgment.get("type") != "ACK"
            or acknowledgment.get("run_id") != run_id
            or acknowledgment.get("sequence") != sequence
            or acknowledgment.get("nonce_a") != nonce_a
            or not isinstance(accepted, bool)
        ):
            raise ValueError("Invalid proposed-protocol ACK")
        ack_transcript = finish_transcript + str(accepted).lower().encode("ascii")
        if not hmac.compare_digest(
            proposed_mac_hex(alice_session_key, "BOB_ACK", ack_transcript),
            str(acknowledgment.get("mac_b", "")).lower(),
        ):
            raise RuntimeError("Proposed protocol BOB_ACK confirmation failed")

        if accepted != bool(alice_gate and response_core["rssi_bob_ok"]):
            raise RuntimeError("Proposed protocol ACK decision does not match both RSSI gates")
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        return elapsed_ms, total_bytes, accepted, alice_gate, response_core["rssi_bob_ok"]
    finally:
        connection.close()


def summarize(values: list[float]) -> dict:
    ordered = sorted(values)
    mean = statistics.mean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    ci95 = 1.96 * sd / math.sqrt(len(values))
    return {
        "n": len(values),
        "mean_ms": round(mean, 4),
        "sd_ms": round(sd, 4),
        "ci95_low_ms": round(mean - ci95, 4),
        "ci95_high_ms": round(mean + ci95, 4),
        "median_ms": round(statistics.median(values), 4),
        "p95_ms": round(ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)], 4),
        "min_ms": round(min(values), 4),
        "max_ms": round(max(values), 4),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=200, help="Handshakes per protocol per network")
    parser.add_argument("--warmup", type=int, default=15, help="Warmup handshakes")
    parser.add_argument("--mldsa-cert-bytes", type=int, default=DEFAULT_MLDSA_CERT_CHAIN_BYTES)
    parser.add_argument("--kemtls-cert-bytes", type=int, default=DEFAULT_KEMTLS_CERT_CHAIN_BYTES)
    parser.add_argument("--no-netem", action="store_true", help="Skip tc netem (measure raw localhost TCP only)")
    parser.add_argument("--output-dir", type=Path, default=Path("./tcp_pq_benchmark_outputs"))
    parser.add_argument("--alice-rssi-baseline-dbm", type=float, default=DEFAULT_RSSI_BASELINES_DBM["alice"])
    parser.add_argument("--bob-rssi-baseline-dbm", type=float, default=DEFAULT_RSSI_BASELINES_DBM["bob"])
    parser.add_argument("--alice-rssi-dbm", type=float, default=DEFAULT_RSSI_BASELINES_DBM["alice"])
    parser.add_argument("--bob-rssi-dbm", type=float, default=DEFAULT_RSSI_BASELINES_DBM["bob"])
    parser.add_argument("--rssi-tolerance-db", type=float, default=4.0)
    args = parser.parse_args()
    if args.rssi_tolerance_db <= 0 or not all(math.isfinite(value) for value in (
        args.alice_rssi_baseline_dbm,
        args.bob_rssi_baseline_dbm,
        args.alice_rssi_dbm,
        args.bob_rssi_dbm,
        args.rssi_tolerance_db,
    )):
        parser.error("RSSI baselines/readings must be finite and tolerance must be positive")

    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Start background TCP servers
    tls_ready, tls_stop = multiprocessing.Event(), multiprocessing.Event()
    kemtls_ready, kemtls_stop = multiprocessing.Event(), multiprocessing.Event()

    p_tls = multiprocessing.Process(
        target=run_tls_mldsa_server,
        args=(PORT_TLS, args.mldsa_cert_bytes, tls_ready, tls_stop),
        daemon=True,
    )
    p_kemtls = multiprocessing.Process(
        target=run_kemtls_server,
        args=(PORT_KEMTLS, args.kemtls_cert_bytes, kemtls_ready, kemtls_stop),
        daemon=True,
    )
    p_tls.start()
    p_kemtls.start()
    tls_ready.wait(timeout=5)
    kemtls_ready.wait(timeout=5)

    scenarios = [{"name": "Localhost_Unshaped", "rate_kbit": 0, "delay_ms": 0.0, "jitter_ms": 0.0}]
    if not args.no_netem:
        scenarios.extend(NETWORK_PROFILES)

    raw_samples = []
    summary_rows = []
    proposed_rssi_raw_samples = []
    proposed_rssi_summary_rows = []
    proposed_server = None
    proposed_stop = None
    proposed_ready_queue = None
    alice_identity_kem = None
    alice_key_setup = None
    bob_key_setup = None

    try:
        for sc in scenarios:
            netem_active = False
            if sc["rate_kbit"] > 0:
                netem_active = apply_tc_netem(sc["rate_kbit"], sc["delay_ms"], sc["jitter_ms"])
                if not netem_active:
                    print(f"Skipping network scenario {sc['name']} due to missing sudo/tc permissions.")
                    continue
            else:
                clear_tc_netem()

            print(f"\n=== Running Scenario: {sc['name']} ({args.iterations} iterations) ===")

            # Warmup
            for _ in range(args.warmup):
                client_handshake_tls_mldsa(PORT_TLS)
                client_handshake_kemtls(PORT_KEMTLS)

            for proto in PROTOCOLS:
                latencies = []
                wire_bytes_list = []
                for i in range(1, args.iterations + 1):
                    if proto == PROTO_TLS_MLDSA:
                        ms, b = client_handshake_tls_mldsa(PORT_TLS)
                    else:
                        ms, b = client_handshake_kemtls(PORT_KEMTLS)
                    latencies.append(ms)
                    wire_bytes_list.append(b)
                    raw_samples.append({
                        "scenario": sc["name"],
                        "protocol": proto,
                        "iteration": i,
                        "handshake_ms": f"{ms:.6f}",
                        "wire_bytes": b,
                    })

                stats = summarize(latencies)
                avg_bytes = int(statistics.mean(wire_bytes_list))
                row = {
                    "scenario": sc["name"],
                    "protocol": proto,
                    "wire_bytes": avg_bytes,
                    **stats,
                }
                summary_rows.append(row)
                print(
                    f"  {proto:<24} | Wire={avg_bytes:>6} B | "
                    f"Mean={stats['mean_ms']:>8.3f} ms | P95={stats['p95_ms']:>8.3f} ms | "
                    f"95%CI=[{stats['ci95_low_ms']:.3f}, {stats['ci95_high_ms']:.3f}]"
                )

        alice_identity_kem = oqs.KeyEncapsulation("ML-KEM-768")
        alice_key_setup_cpu_started = time.process_time_ns()
        alice_key_setup_started = time.perf_counter_ns()
        alice_identity_public_key = alice_identity_kem.generate_keypair()
        alice_key_setup = {
            "cpu_ms": (time.process_time_ns() - alice_key_setup_cpu_started) / 1_000_000,
            "wall_ms": (time.perf_counter_ns() - alice_key_setup_started) / 1_000_000,
        }
        alice_fingerprint = hashlib.sha256(alice_identity_public_key).hexdigest()
        proposed_ready_queue = multiprocessing.Queue()
        proposed_stop = multiprocessing.Event()
        proposed_server = multiprocessing.Process(
            target=run_proposed_rssi_server,
            args=(
                PORT_RSSI_GATED,
                alice_identity_public_key,
                alice_fingerprint,
                args.bob_rssi_baseline_dbm,
                args.bob_rssi_dbm,
                args.rssi_tolerance_db,
                proposed_ready_queue,
                proposed_stop,
            ),
            daemon=True,
        )
        proposed_server.start()
        try:
            bob_identity_public_key, bob_fingerprint, bob_key_setup = proposed_ready_queue.get(timeout=10)
        except queue.Empty as error:
            raise RuntimeError("Proposed RSSI protocol server did not provision its identity key") from error
        if not hmac.compare_digest(
            hashlib.sha256(bob_identity_public_key).hexdigest(), bob_fingerprint
        ):
            raise RuntimeError("Proposed protocol Bob public-key pin check failed")

        for sc in scenarios:
            if sc["rate_kbit"] > 0:
                if not apply_tc_netem(sc["rate_kbit"], sc["delay_ms"], sc["jitter_ms"]):
                    print(f"Skipping proposed RSSI protocol scenario {sc['name']} because tc netem could not be applied.")
                    continue
            else:
                clear_tc_netem()

            for warmup_index in range(args.warmup):
                client_handshake_proposed_rssi(
                    PORT_RSSI_GATED,
                    alice_identity_kem,
                    alice_identity_public_key,
                    alice_fingerprint,
                    bob_identity_public_key,
                    bob_fingerprint,
                    warmup_index,
                    args.alice_rssi_baseline_dbm,
                    args.alice_rssi_dbm,
                    args.rssi_tolerance_db,
                )

            latency_samples = []
            application_frame_bytes = []
            for iteration in range(1, args.iterations + 1):
                latency_ms, frame_bytes, accepted, alice_gate, bob_gate = client_handshake_proposed_rssi(
                    PORT_RSSI_GATED,
                    alice_identity_kem,
                    alice_identity_public_key,
                    alice_fingerprint,
                    bob_identity_public_key,
                    bob_fingerprint,
                    iteration,
                    args.alice_rssi_baseline_dbm,
                    args.alice_rssi_dbm,
                    args.rssi_tolerance_db,
                )
                latency_samples.append(latency_ms)
                application_frame_bytes.append(frame_bytes)
                proposed_rssi_raw_samples.append({
                    "scenario": sc["name"],
                    "protocol": PROTO_RSSI_GATED,
                    "iteration": iteration,
                    "handshake_ms": f"{latency_ms:.6f}",
                    "application_frame_bytes": frame_bytes,
                    "alice_rssi_gate_pass": alice_gate,
                    "bob_rssi_gate_pass": bob_gate,
                    "accepted": accepted,
                })

            stats = summarize(latency_samples)
            accepted_count = sum(
                row["accepted"] for row in proposed_rssi_raw_samples
                if row["scenario"] == sc["name"]
            )
            alice_gate_pass_count = sum(
                row["alice_rssi_gate_pass"] for row in proposed_rssi_raw_samples
                if row["scenario"] == sc["name"]
            )
            bob_gate_pass_count = sum(
                row["bob_rssi_gate_pass"] for row in proposed_rssi_raw_samples
                if row["scenario"] == sc["name"]
            )
            proposed_rssi_summary_rows.append({
                "scenario": sc["name"],
                "protocol": PROTO_RSSI_GATED,
                "application_frame_bytes_mean": statistics.mean(application_frame_bytes),
                "alice_gate_pass_n": alice_gate_pass_count,
                "bob_gate_pass_n": bob_gate_pass_count,
                "accepted_n": accepted_count,
                "accepted_rate": accepted_count / args.iterations,
                **stats,
            })
            print(
                f"  {PROTO_RSSI_GATED:<24} | Application bytes={statistics.mean(application_frame_bytes):>6.0f} B | "
                f"Mean={stats['mean_ms']:>8.3f} ms | P95={stats['p95_ms']:>8.3f} ms | "
                f"Accepted={accepted_count}/{args.iterations} (RSSI inputs are synthetic)"
            )

    finally:
        clear_tc_netem()
        if proposed_stop is not None:
            proposed_stop.set()
        if proposed_server is not None:
            proposed_server.join(timeout=2)
            if proposed_server.is_alive():
                proposed_server.terminate()
                proposed_server.join(timeout=2)
        if alice_identity_kem is not None:
            alice_identity_kem.free()
        if proposed_ready_queue is not None:
            proposed_ready_queue.close()
            proposed_ready_queue.join_thread()
        tls_stop.set()
        kemtls_stop.set()
        p_tls.join(timeout=2)
        p_kemtls.join(timeout=2)

    # Export results
    if summary_rows:
        summary_csv = out_dir / "tcp_protocol_summary.csv"
        with summary_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(summary_rows[0]))
            writer.writeheader()
            writer.writerows(summary_rows)

        samples_csv = out_dir / "tcp_protocol_samples.csv"
        with samples_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(raw_samples[0]))
            writer.writeheader()
            writer.writerows(raw_samples)

        if proposed_rssi_summary_rows:
            proposed_summary_csv = out_dir / "proposed_rssi_protocol_summary.csv"
            with proposed_summary_csv.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(proposed_rssi_summary_rows[0]))
                writer.writeheader()
                writer.writerows(proposed_rssi_summary_rows)

            proposed_samples_csv = out_dir / "proposed_rssi_protocol_samples.csv"
            with proposed_samples_csv.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(proposed_rssi_raw_samples[0]))
                writer.writeheader()
                writer.writerows(proposed_rssi_raw_samples)

        meta = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(),
            "nist_algorithms": {"kem": "ML-KEM-768 (FIPS 203)", "sig": "ML-DSA-65 (FIPS 204)"},
            "iterations": args.iterations,
            "mldsa_cert_chain_bytes": args.mldsa_cert_bytes,
            "kemtls_cert_chain_bytes": args.kemtls_cert_bytes,
            "proposed_rssi_protocol": {
                "protocol_id": RSSI_PROTOCOL_ID,
                "implementation_scope": "Proposed four-message protocol over local TCP; this is not the raw 802.11 implementation or an official KEMTLS implementation.",
                "kem": "ML-KEM-768 with long-term identity key pairs for both endpoints; no forward secrecy.",
                "identity_binding": "SHA-256 fingerprints of raw liboqs public-key bytes pinned in-process before measurements.",
                "rssi_input_source": "Synthetic CLI values; loopback TCP provides no physical RSSI measurement.",
                "alice_baseline_dbm": args.alice_rssi_baseline_dbm,
                "bob_baseline_dbm": args.bob_rssi_baseline_dbm,
                "alice_observed_dbm": args.alice_rssi_dbm,
                "bob_observed_dbm": args.bob_rssi_dbm,
                "tolerance_db": args.rssi_tolerance_db,
                "setup_timings": {
                    "alice_identity_keypair": alice_key_setup,
                    "bob_identity_keypair": bob_key_setup,
                },
                "sample_count_per_scenario": args.iterations,
                "outputs": [
                    "proposed_rssi_protocol_samples.csv",
                    "proposed_rssi_protocol_summary.csv",
                ] if proposed_rssi_summary_rows else [],
            },
        }
        (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        print(f"\nResults successfully saved to: {out_dir}")


if __name__ == "__main__":
    main()