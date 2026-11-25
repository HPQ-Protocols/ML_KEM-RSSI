#!/usr/bin/env python3
"""Alice initiator for pinned-key ML-KEM-768 plus a calibrated RSSI gate."""

import argparse
import csv
import hashlib
import math
import queue
import secrets
import sys
import threading
import time

try:
    from scapy.all import AsyncSniffer, PcapWriter, conf
except ImportError as error:
    raise SystemExit("[ALICE ERROR] Scapy thiếu; cài Scapy trên Ubuntu.") from error

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

MAC_ALICE = "02:00:00:00:00:01"
MAC_BOB = "02:00:00:00:00:02"


class Alice:
    def __init__(self, args):
        self.args = args
        self.inbox = queue.Queue(maxsize=2048)
        self.stop_event = threading.Event()
        self.rx_count = 0
        self.tx_count = 0
        self.samples = []
        self.sequence = 0
        self.pcap = None
        self.socket = None
        self.tx_file = None
        self.rx_file = None
        self.baseline = None
        self.own_fingerprint = None
        self.peer_fingerprint = None

    def record(self, writer, file_handle, row):
        writer.writerow(row)
        file_handle.flush()

    def on_packet(self, packet):
        if self.pcap is not None:
            self.pcap.write(packet)
        message = decode_message(packet)
        if not message or message.get("type") not in {"RESP", "ACK"}:
            return
        if (packet["Dot11"].addr2 or "").lower() != MAC_BOB:
            return
        try:
            self.inbox.put_nowait((message, read_rssi(packet)))
        except queue.Full:
            print("[ALICE WARNING] Receive queue đầy; bỏ frame mới nhất", file=sys.stderr)

    def send(self, message):
        payload = encode_message(message)
        self.socket.send(make_frame(payload, MAC_ALICE))
        self.tx_count += 1

    def wait_for(self, kind, sequence, nonce_a, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                message, rssi = self.inbox.get(timeout=min(0.25, deadline - time.monotonic()))
            except queue.Empty:
                continue
            if (message.get("type") == kind and message.get("run_id") == self.args.run_id
                    and message.get("sequence") == sequence and message.get("nonce_a") == nonce_a):
                return message, rssi
        return None, None

    def handshake(self, sequence):
        ciphertext_a, secret_a = kem_encapsulate(self.args.peer_public)
        nonce_a = secrets.token_hex(16)
        init = {
            "protocol": PROTOCOL,
            "type": "INIT",
            "run_id": self.args.run_id,
            "sequence": sequence,
            "nonce_a": nonce_a,
            "alice_fingerprint": self.own_fingerprint,
            "ciphertext_a": b64encode(ciphertext_a),
        }
        init_payload = encode_message(init)
        self.socket.send(make_frame(init_payload, MAC_ALICE))
        self.tx_count += 1
        self.record(self.tx_writer, self.tx_file, [
            self.args.run_id, sequence, nonce_a,
            hashlib.sha256(init_payload).hexdigest(), "sent",
        ])
        response, received_rssi = self.wait_for("RESP", sequence, nonce_a, self.args.timeout)
        if response is None:
            return {"sequence": sequence, "nonce_a": nonce_a, "status": "TIMEOUT_RESPONSE", "rssi": received_rssi}
        if response.get("bob_fingerprint") != self.peer_fingerprint:
            return {"sequence": sequence, "nonce_a": nonce_a, "status": "REJECTED_PEER_FINGERPRINT", "rssi": received_rssi}
        nonce_b = response.get("nonce_b")
        if (not isinstance(nonce_b, str) or len(nonce_b) != 32
                or any(char not in "0123456789abcdef" for char in nonce_b)):
            return {"sequence": sequence, "nonce_a": nonce_a, "status": "REJECTED_MALFORMED_RESPONSE", "rssi": received_rssi}
        try:
            ciphertext_b = b64decode(response.get("ciphertext_b", ""), 1088)
            secret_b = kem_decapsulate(self.args.identity_private, ciphertext_b)
            response_core = {key: value for key, value in response.items() if key != "mac_b"}
            transcript = transcript_bytes(init, response_core)
            session_key = derive_session_key(secret_a, secret_b, transcript)
        except (ValueError, RuntimeError, KeyError) as error:
            return {"sequence": sequence, "nonce_a": nonce_a, "status": f"REJECTED_KEM:{error}", "rssi": received_rssi}
        if not verify_mac(session_key, "BOB_RESP", transcript, response.get("mac_b", "")):
            return {"sequence": sequence, "nonce_a": nonce_a, "status": "REJECTED_BOB_KEY_CONFIRMATION", "rssi": received_rssi}
        if received_rssi is None:
            return {"sequence": sequence, "nonce_a": nonce_a, "status": "REJECTED_RSSI_UNAVAILABLE", "rssi": received_rssi}
        if self.args.mode == "calibrate":
            alice_rssi_ok = True
        else:
            alice_rssi_ok = rssi_within_baseline(received_rssi, self.baseline, self.args.rssi_tolerance_db)
        finish_core = make_finish_core(
            self.args.run_id, sequence, nonce_a, nonce_b, alice_rssi_ok,
        )
        finish_transcript = transcript + canonical_json(finish_core)
        finish = dict(finish_core)
        finish["mac_a"] = mac_hex(session_key, "ALICE_FINISH", finish_transcript)
        self.send(finish)
        acknowledgment, _ = self.wait_for("ACK", sequence, nonce_a, self.args.timeout)
        if acknowledgment is None:
            return {"sequence": sequence, "nonce_a": nonce_a, "status": "TIMEOUT_ACK", "rssi": received_rssi, "rssi_ok": alice_rssi_ok}
        accepted = acknowledgment.get("accepted") is True
        expected_ack = mac_hex(session_key, "BOB_ACK", finish_transcript + str(accepted).lower().encode("ascii"))
        if not secrets.compare_digest(expected_ack, str(acknowledgment.get("mac_b", "")).lower()):
            return {"sequence": sequence, "nonce_a": nonce_a, "status": "REJECTED_BOB_ACK", "rssi": received_rssi, "rssi_ok": alice_rssi_ok}
        if self.args.mode == "calibrate" and accepted:
            self.samples.append(received_rssi)
        status = "AUTHENTICATED" if accepted else "REJECTED_RSSI_GATE"
        return {"sequence": sequence, "nonce_a": nonce_a, "status": status, "rssi": received_rssi, "rssi_ok": alice_rssi_ok}

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
        self.tx_file = open(self.args.out_tx, "w", newline="", encoding="utf-8")
        self.rx_file = open(self.args.out_rx, "w", newline="", encoding="utf-8")
        self.tx_writer = csv.writer(self.tx_file)
        self.rx_writer = csv.writer(self.rx_file)
        self.tx_writer.writerow(["run_id", "sequence", "nonce_a", "init_sha256", "send_status"])
        self.rx_writer.writerow(["run_id", "sequence", "nonce_a", "rx_rssi_dbm", "rssi_ok", "status"])
        self.tx_file.flush()
        self.rx_file.flush()
        self.sniffer = AsyncSniffer(iface=self.args.interface, prn=self.on_packet, store=False)
        self.sniffer.start()
        time.sleep(0.2)
        started = time.monotonic()
        print(f"[ALICE] mode={self.args.mode} run_id={self.args.run_id} own_fp={self.own_fingerprint}")
        try:
            while time.monotonic() - started < self.args.duration:
                if self.args.mode == "calibrate" and len(self.samples) >= self.args.calibration_sessions:
                    break
                sequence = self.sequence
                self.sequence += 1
                try:
                    result = self.handshake(sequence)
                    if result["status"] != "TIMEOUT_RESPONSE":
                        self.rx_count += 1
                    self.record(self.rx_writer, self.rx_file, [
                        self.args.run_id, sequence, result["nonce_a"], result.get("rssi"),
                        result.get("rssi_ok", ""), result["status"],
                    ])
                    print(f"[ALICE {result['status']}] seq={sequence} RSSI={result.get('rssi')}")
                except (OSError, RuntimeError, ValueError) as error:
                    print(f"[ALICE SESSION ERROR] seq={sequence}: {error}", file=sys.stderr)
                time.sleep(self.args.interval)
        finally:
            self.stop_event.set()
            if self.sniffer is not None:
                if self.sniffer.running:
                    self.sniffer.stop(join=False)
                self.sniffer.join()
            if self.pcap is not None:
                self.pcap.close()
            self.tx_file.close()
            self.rx_file.close()
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
            print(f"[ALICE BASELINE SAVED] n={baseline['sample_count']} median={baseline['median_rssi_dbm']:.2f} dBm")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface")
    parser.add_argument("--mode", choices=("calibrate", "evaluate"), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--identity-private", required=True)
    parser.add_argument("--identity-public", required=True)
    parser.add_argument("--peer-public", required=True)
    parser.add_argument("--peer-fingerprint", required=True)
    parser.add_argument("--baseline", default="alice_rssi_baseline.json")
    parser.add_argument("--calibration-sessions", type=int, default=20)
    parser.add_argument("--rssi-tolerance-db", type=float, default=4.0)
    parser.add_argument("--channel", type=int, default=5)
    parser.add_argument("--width", choices=("HT20", "HT40+", "HT40-"), default="HT20")
    parser.add_argument("--duration", type=float, default=300.0)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--out-tx", default="alice_tx_log.csv")
    parser.add_argument("--out-rx", default="alice_rx_log.csv")
    parser.add_argument("--pcap", default="alice_raw.pcap")
    args = parser.parse_args()
    if len(args.run_id) != 16 or any(char not in "0123456789abcdef" for char in args.run_id):
        parser.error("--run-id phải là 16 ký tự hex viết thường và phải giống trên Alice/Bob/Eva")
    if args.duration <= 0 or args.interval <= 0 or args.timeout <= 0:
        parser.error("duration, interval và timeout phải dương")
    if args.calibration_sessions < 10:
        parser.error("calibration-sessions tối thiểu là 10")
    if not math.isfinite(args.rssi_tolerance_db) or args.rssi_tolerance_db <= 0:
        parser.error("rssi-tolerance-db phải là số hữu hạn dương")
    return args


def main():
    try:
        Alice(parse_args()).run()
    except (OSError, RuntimeError, ValueError, PermissionError) as error:
        sys.exit(f"[ALICE ERROR] {error}")


if __name__ == "__main__":
    main()