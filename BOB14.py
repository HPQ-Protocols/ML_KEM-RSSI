#!/usr/bin/env python3
"""Bob responder for pinned-key ML-KEM-768 plus a calibrated RSSI gate."""

import argparse
import csv
import hashlib
import hmac
import math
import secrets
import statistics
import subprocess
import sys
import threading
import time
from collections import deque

try:
    from scapy.all import AsyncSniffer, PcapWriter, conf
except ImportError as error:
    raise SystemExit("[BOB ERROR] Scapy thiếu; cài Scapy trên Ubuntu.") from error

from tk9_protocol13 import (
    PROTOCOL,
    b64decode,
    b64encode,
    canonical_json,
    create_baseline,
    decode_message,
    derive_session_key,
    encode_message,
    kem_decapsulate,
    kem_encapsulate,
    load_baseline,
    load_private_identity,
    mac_hex,
    make_finish_core,
    make_frame,
    read_rssi,
    rssi_within_baseline,
    set_monitor_channel,
    transcript_bytes,
    validate_peer_key,
    verify_mac,
)

MAC_BOB = "02:00:00:00:00:02"


class Bob:
    def __init__(self, args):
        self.args = args
        self.own_fingerprint = None
        self.peer_fingerprint = None
        self.baseline = None
        self.samples = []
        self.pending = {}
        self.seen_nonces = set()
        self.nonce_order = deque()
        self.socket = None
        self.pcap = None
        self.sniffer = None
        self.csv_file = None
        self.writer = None
        self.stop_event = threading.Event()
        self.accepted_count = 0
        self.received_count = 0

    def log(self, message, rssi, hmac_valid, decision, rssi_ok=""):
        dot11 = message.get("_source_mac", "")
        self.writer.writerow([
            f"{time.time():.6f}", self.args.mode, self.args.run_id,
            message.get("sequence", ""), message.get("nonce_a", ""), dot11,
            message.get("alice_fingerprint", ""), "" if rssi is None else f"{rssi:.2f}",
            rssi_ok, hmac_valid, decision,
        ])
        self.csv_file.flush()

    def send(self, message):
        self.socket.send(make_frame(encode_message(message), MAC_BOB))

    def remember_nonce(self, nonce):
        if nonce in self.seen_nonces:
            return False
        self.seen_nonces.add(nonce)
        self.nonce_order.append(nonce)
        if len(self.nonce_order) > 8192:
            oldest = self.nonce_order.popleft()
            self.seen_nonces.discard(oldest)
        return True

    def expire_pending(self):
        now = time.monotonic()
        expired = [nonce for nonce, state in self.pending.items() if now - state["created"] > self.args.pending_timeout]
        for nonce in expired:
            state = self.pending.pop(nonce)
            message = state["init"]
            self.log(message, state["rssi"], "", "REJECTED_FINISH_TIMEOUT", state["rssi_ok"])

    def handle_init(self, message, rssi, source_mac):
        self.received_count += 1
        message["_source_mac"] = source_mac or ""
        nonce_a = message.get("nonce_a")
        sequence = message.get("sequence")
        if message.get("run_id") != self.args.run_id:
            self.log(message, rssi, "", "REJECTED_RUN_ID")
            return
        if (not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0
                or not isinstance(nonce_a, str) or len(nonce_a) != 32
                or any(char not in "0123456789abcdef" for char in nonce_a)):
            self.log(message, rssi, "", "REJECTED_MALFORMED_INIT")
            return
        if message.get("alice_fingerprint") != self.peer_fingerprint:
            self.log(message, rssi, "", "REJECTED_PEER_FINGERPRINT")
            return
        if not self.remember_nonce(nonce_a):
            self.log(message, rssi, "", "REJECTED_REPLAY")
            return
        if nonce_a in self.pending or len(self.pending) >= 64:
            self.log(message, rssi, "", "REJECTED_PENDING_LIMIT")
            return
        if rssi is None:
            self.log(message, rssi, "", "REJECTED_RSSI_UNAVAILABLE")
            return
        try:
            ciphertext_a = b64decode(message.get("ciphertext_a", ""), 1088)
            secret_a = kem_decapsulate(self.args.identity_private, ciphertext_a)
            ciphertext_b, secret_b = kem_encapsulate(self.args.peer_public)
        except (RuntimeError, ValueError, KeyError) as error:
            self.log(message, rssi, False, f"REJECTED_KEM:{error}")
            return
        if self.args.mode == "calibrate":
            rssi_ok = True
        else:
            rssi_ok = rssi_within_baseline(rssi, self.baseline, self.args.rssi_tolerance_db)
        init_core = {key: value for key, value in message.items() if not key.startswith("_")}
        response_core = {
            "protocol": PROTOCOL,
            "type": "RESP",
            "run_id": self.args.run_id,
            "sequence": sequence,
            "nonce_a": nonce_a,
            "nonce_b": secrets.token_hex(16),
            "bob_fingerprint": self.own_fingerprint,
            "ciphertext_b": b64encode(ciphertext_b),
            "rssi_bob_ok": rssi_ok,
        }
        transcript = transcript_bytes(init_core, response_core)
        session_key = derive_session_key(secret_a, secret_b, transcript)
        response = dict(response_core)
        response["mac_b"] = mac_hex(session_key, "BOB_RESP", transcript)
        self.pending[nonce_a] = {
            "created": time.monotonic(),
            "init": message,
            "sequence": sequence,
            "nonce_b": response_core["nonce_b"],
            "transcript": transcript,
            "session_key": session_key,
            "rssi": rssi,
            "rssi_ok": rssi_ok,
        }
        self.log(message, rssi, "", "PENDING_FINISH", rssi_ok)
        self.send(response)

    def handle_finish(self, message):
        nonce_a = message.get("nonce_a")
        if (not isinstance(nonce_a, str) or len(nonce_a) != 32
                or any(char not in "0123456789abcdef" for char in nonce_a)):
            self.log(message, None, False, "REJECTED_MALFORMED_FINISH")
            return
        state = self.pending.get(nonce_a)
        if state is None:
            self.log(message, None, False, "REJECTED_NO_PENDING_SESSION")
            return
        if (message.get("run_id") != self.args.run_id
                or message.get("sequence") != state["sequence"]
                or message.get("nonce_b") != state["nonce_b"]):
            self.pending.pop(nonce_a, None)
            self.log(message, state["rssi"], False, "REJECTED_TRANSCRIPT_MISMATCH", state["rssi_ok"])
            return
        try:
            finish_core = make_finish_core(
                self.args.run_id,
                state["sequence"],
                nonce_a,
                state["nonce_b"],
                message.get("alice_rssi_ok") is True,
            )
        except ValueError:
            self.pending.pop(nonce_a, None)
            self.log(message, state["rssi"], False, "REJECTED_MALFORMED_FINISH", state["rssi_ok"])
            return
        finish_transcript = state["transcript"] + canonical_json(finish_core)
        valid_mac = verify_mac(state["session_key"], "ALICE_FINISH", finish_transcript, message.get("mac_a", ""))
        accepted = valid_mac and state["rssi_ok"] and finish_core["alice_rssi_ok"]
        self.pending.pop(nonce_a, None)
        if valid_mac and accepted and self.args.mode == "calibrate":
            self.samples.append(state["rssi"])
        decision = "AUTHENTICATED" if accepted else (
            "REJECTED_RSSI_GATE" if valid_mac else "REJECTED_ALICE_KEY_CONFIRMATION"
        )
        self.log(state["init"], state["rssi"], valid_mac, decision, state["rssi_ok"])
        self.accepted_count += int(accepted)
        acknowledgment = {
            "protocol": PROTOCOL,
            "type": "ACK",
            "run_id": self.args.run_id,
            "sequence": state["sequence"],
            "nonce_a": nonce_a,
            "accepted": bool(accepted),
        }
        acknowledgment["mac_b"] = mac_hex(
            state["session_key"], "BOB_ACK",
            finish_transcript + str(bool(accepted)).lower().encode("ascii"),
        )
        self.send(acknowledgment)
        print(f"[BOB {decision}] seq={state['sequence']} RSSI={state['rssi']:.1f} dBm")
        if self.args.mode == "calibrate" and len(self.samples) >= self.args.calibration_sessions:
            self.stop_event.set()

    def on_packet(self, packet):
        if self.pcap is not None:
            self.pcap.write(packet)
        message = decode_message(packet)
        if not message:
            return
        self.expire_pending()
        if message.get("type") == "INIT":
            self.handle_init(message, read_rssi(packet), packet["Dot11"].addr2)
        elif message.get("type") == "FINISH":
            self.handle_finish(message)

    def run(self):
        self.own_fingerprint = load_private_identity(self.args.identity_private, self.args.identity_public)
        self.peer_fingerprint = validate_peer_key(self.args.peer_public, self.args.peer_fingerprint)
        if self.args.mode == "evaluate":
            self.baseline = load_baseline(
                self.args.baseline, self.own_fingerprint, self.peer_fingerprint,
                self.args.channel, self.args.width,
            )
        set_monitor_channel(self.args.interface, self.args.channel, self.args.width)
        self.socket = conf.L2socket(iface=self.args.interface)
        self.pcap = PcapWriter(self.args.pcap, append=False, sync=True) if self.args.pcap else None
        self.csv_file = open(self.args.out, "w", newline="", encoding="utf-8")
        self.writer = csv.writer(self.csv_file)
        self.writer.writerow([
            "rx_time_unix", "mode", "run_id", "sequence", "nonce_a", "source_mac",
            "claimed_fingerprint", "rssi_dbm", "rssi_ok", "auth_hmac_valid", "decision",
        ])
        self.csv_file.flush()
        print(f"[BOB] mode={self.args.mode} run_id={self.args.run_id} own_fp={self.own_fingerprint}")
        try:
            self.sniffer = AsyncSniffer(
                iface=self.args.interface,
                prn=self.on_packet,
                store=False,
            )
            self.sniffer.start()
            deadline = time.monotonic() + self.args.duration
            while time.monotonic() < deadline and not self.stop_event.wait(0.1):
                pass
        except KeyboardInterrupt:
            print("\n[BOB] Interrupted")
        finally:
            if self.sniffer is not None:
                if self.sniffer.running:
                    self.sniffer.stop(join=False)
                self.sniffer.join()
            self.expire_pending()
            for nonce_a, state in list(self.pending.items()):
                self.log(state["init"], state["rssi"], "", "REJECTED_FINISH_TIMEOUT", state["rssi_ok"])
                self.pending.pop(nonce_a, None)
            if self.pcap is not None:
                self.pcap.close()
            if self.csv_file is not None:
                self.csv_file.close()
            if self.socket is not None:
                self.socket.close()
        if self.args.mode == "calibrate":
            if len(self.samples) < self.args.calibration_sessions:
                raise RuntimeError(
                    f"Calibration chưa đủ: {len(self.samples)}/{self.args.calibration_sessions} phiên ACCEPTED"
                )
            baseline = create_baseline(
                self.args.baseline, self.own_fingerprint, self.peer_fingerprint,
                self.args.channel, self.args.width, self.samples,
            )
            print(f"[BOB BASELINE SAVED] n={baseline['sample_count']} median={baseline['median_rssi_dbm']:.2f} dBm")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface")
    parser.add_argument("--mode", choices=("calibrate", "evaluate"), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--identity-private", required=True)
    parser.add_argument("--identity-public", required=True)
    parser.add_argument("--peer-public", required=True)
    parser.add_argument("--peer-fingerprint", required=True)
    parser.add_argument("--baseline", default="bob_rssi_baseline.json")
    parser.add_argument("--calibration-sessions", type=int, default=20)
    parser.add_argument("--rssi-tolerance-db", type=float, default=4.0)
    parser.add_argument("--channel", type=int, default=5)
    parser.add_argument("--width", choices=("HT20", "HT40+", "HT40-"), default="HT20")
    parser.add_argument("--duration", type=float, default=300.0)
    parser.add_argument("--pending-timeout", type=float, default=8.0)
    parser.add_argument("--out", default="bob_rx_log.csv")
    parser.add_argument("--pcap", default="bob_rx.pcap")
    args = parser.parse_args()
    if len(args.run_id) != 16 or any(char not in "0123456789abcdef" for char in args.run_id):
        parser.error("--run-id phải là 16 ký tự hex viết thường và phải giống trên Alice/Bob/Eva")
    if args.duration <= 0 or args.pending_timeout <= 0:
        parser.error("duration và pending-timeout phải dương")
    if args.calibration_sessions < 10:
        parser.error("calibration-sessions tối thiểu là 10")
    if not math.isfinite(args.rssi_tolerance_db) or args.rssi_tolerance_db <= 0:
        parser.error("rssi-tolerance-db phải là số hữu hạn dương")
    return args


def main():
    try:
        Bob(parse_args()).run()
    except (OSError, RuntimeError, ValueError, PermissionError) as error:
        sys.exit(f"[BOB ERROR] {error}")


if __name__ == "__main__":
    main()