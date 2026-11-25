#!/usr/bin/env python3
"""Controlled active impersonation test using an invalid Alice FINISH MAC."""

import argparse
import csv
import hashlib
import math
import queue
import secrets
import sys
import threading
import time
from collections import Counter

try:
    from scapy.all import AsyncSniffer, PcapWriter, conf
except ImportError as error:
    raise SystemExit("[EVA ERROR] Scapy thiếu; cài Scapy trên Ubuntu.") from error

from tk9_protocol14 import (
    PROTOCOL,
    b64decode,
    b64encode,
    decode_message,
    encode_message,
    kem_encapsulate,
    make_finish_core,
    make_frame,
    read_rssi,
    set_monitor_channel,
    valid_hex_token,
    validate_peer_key,
)

MAC_BOB = "02:00:00:00:00:02"
SPOOF_MAC_ALICE = "02:00:00:00:00:01"


class ActiveEva:
    def __init__(self, args):
        self.args = args
        self.inbox = queue.Queue(maxsize=4096)
        self.socket = None
        self.sniffer = None
        self.pcap = None
        self.output_file = None
        self.writer = None
        self.bob_fingerprint = None
        self.events = Counter()

    def record(self, event, sequence, nonce_a, source_mac="", rssi="", bob_fp="", nonce_b="", accepted="", detail=""):
        self.writer.writerow([
            f"{time.time():.6f}", self.args.run_id, sequence, nonce_a, event,
            source_mac, "" if rssi is None else rssi, bob_fp, nonce_b, accepted, detail,
        ])
        self.output_file.flush()
        self.events[event] += 1

    def on_packet(self, packet):
        if self.pcap is not None:
            self.pcap.write(packet)
        message = decode_message(packet)
        if not message or message.get("type") not in {"RESP", "ACK"}:
            return
        source_mac = (packet["Dot11"].addr2 or "").lower()
        if source_mac != MAC_BOB:
            return
        try:
            self.inbox.put_nowait((message, read_rssi(packet), source_mac))
        except queue.Full:
            print("[EVA WARNING] Receive queue đầy; bỏ frame mới nhất", file=sys.stderr)

    def wait_for(self, kind, sequence, nonce_a, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                message, rssi, source_mac = self.inbox.get(
                    timeout=min(0.2, deadline - time.monotonic())
                )
            except queue.Empty:
                continue
            matches = (
                message.get("type") == kind
                and message.get("run_id") == self.args.run_id
                and message.get("sequence") == sequence
                and message.get("nonce_a") == nonce_a
            )
            if matches:
                return message, rssi, source_mac
            self.record(
                "UNMATCHED_RX", message.get("sequence", ""), message.get("nonce_a", ""),
                source_mac, rssi, message.get("bob_fingerprint", ""),
                message.get("nonce_b", ""), message.get("accepted", ""),
                f"unexpected_{message.get('type', 'unknown')}",
            )
        return None, None, ""

    def attempt(self, sequence):
        nonce_a = secrets.token_hex(16)
        ciphertext_a, _ = kem_encapsulate(self.args.bob_public)
        init = {
            "protocol": PROTOCOL,
            "type": "INIT",
            "run_id": self.args.run_id,
            "sequence": sequence,
            "nonce_a": nonce_a,
            "alice_fingerprint": self.args.claimed_alice_fingerprint,
            "ciphertext_a": b64encode(ciphertext_a),
        }
        payload = encode_message(init)
        self.socket.send(make_frame(payload, SPOOF_MAC_ALICE))
        self.record(
            "INIT_SENT", sequence, nonce_a, SPOOF_MAC_ALICE,
            detail=hashlib.sha256(payload).hexdigest(),
        )

        response, rssi, source_mac = self.wait_for(
            "RESP", sequence, nonce_a, self.args.response_timeout
        )
        if response is None:
            self.record("RESP_TIMEOUT", sequence, nonce_a, detail="Bob did not reply in time")
            return
        if response.get("bob_fingerprint") != self.bob_fingerprint:
            self.record(
                "RESP_REJECTED", sequence, nonce_a, source_mac, rssi,
                response.get("bob_fingerprint", ""), response.get("nonce_b", ""),
                detail="Bob fingerprint mismatch",
            )
            return
        nonce_b = response.get("nonce_b")
        if not valid_hex_token(nonce_b, 32):
            self.record(
                "RESP_REJECTED", sequence, nonce_a, source_mac, rssi,
                self.bob_fingerprint, detail="Malformed nonce_b",
            )
            return
        try:
            b64decode(response.get("ciphertext_b", ""), 1088)
        except ValueError as error:
            self.record(
                "RESP_REJECTED", sequence, nonce_a, source_mac, rssi,
                self.bob_fingerprint, nonce_b, detail=f"Malformed ciphertext_b: {error}",
            )
            return
        self.record(
            "RESP_RECEIVED", sequence, nonce_a, source_mac, rssi,
            self.bob_fingerprint, nonce_b,
        )

        if self.args.finish_mode == "withhold":
            self.record(
                "FINISH_WITHHELD", sequence, nonce_a, nonce_b=nonce_b,
                detail="Timeout control; no Alice private key used",
            )
            return

        finish = make_finish_core(
            self.args.run_id, sequence, nonce_a, nonce_b, True,
        )
        finish["mac_a"] = secrets.token_hex(32)
        self.socket.send(make_frame(encode_message(finish), SPOOF_MAC_ALICE))
        self.record(
            "FORGED_FINISH_SENT", sequence, nonce_a, SPOOF_MAC_ALICE,
            rssi, self.bob_fingerprint, nonce_b, detail="random 256-bit MAC",
        )

        acknowledgment, ack_rssi, ack_source = self.wait_for(
            "ACK", sequence, nonce_a, self.args.ack_timeout
        )
        if acknowledgment is None:
            self.record("ACK_TIMEOUT", sequence, nonce_a, detail="No Bob ACK received")
            return
        accepted = acknowledgment.get("accepted") is True
        self.record(
            "ACK_RECEIVED", sequence, nonce_a, ack_source, ack_rssi,
            self.bob_fingerprint, nonce_b, str(accepted).lower(),
            "expected_false" if not accepted else "SECURITY_FAILURE_ACCEPTED",
        )

    def run(self):
        self.bob_fingerprint = validate_peer_key(
            self.args.bob_public, self.args.bob_fingerprint,
        )
        set_monitor_channel(self.args.interface, self.args.channel, self.args.width)
        self.socket = conf.L2socket(iface=self.args.interface)
        self.pcap = PcapWriter(self.args.pcap, append=False, sync=True) if self.args.pcap else None
        self.output_file = open(self.args.out, "w", newline="", encoding="utf-8")
        self.writer = csv.writer(self.output_file)
        self.writer.writerow([
            "timestamp_unix", "run_id", "sequence", "nonce_a", "event",
            "source_mac", "rssi_dbm", "bob_fingerprint", "nonce_b", "accepted", "detail",
        ])
        self.output_file.flush()
        self.sniffer = AsyncSniffer(iface=self.args.interface, prn=self.on_packet, store=False)
        self.sniffer.start()
        time.sleep(0.25)
        started = time.monotonic()
        print(
            f"[EVA ACTIVE] run_id={self.args.run_id} mode={self.args.finish_mode} "
            f"attempts={self.args.attempts} channel={self.args.channel} {self.args.width}"
        )
        try:
            for attempt_index in range(self.args.attempts):
                if time.monotonic() - started >= self.args.duration:
                    print("[EVA WARNING] Duration reached before all attempts were sent", file=sys.stderr)
                    break
                sequence = self.args.start_sequence + attempt_index
                try:
                    self.attempt(sequence)
                except (OSError, RuntimeError, ValueError) as error:
                    self.record(
                        "ATTEMPT_ERROR", sequence, "", detail=f"{type(error).__name__}: {error}",
                    )
                    print(f"[EVA ATTEMPT ERROR] seq={sequence}: {error}", file=sys.stderr)
                if attempt_index + 1 < self.args.attempts:
                    time.sleep(self.args.interval)
        except KeyboardInterrupt:
            print("\n[EVA ACTIVE] Interrupted")
        finally:
            if self.sniffer is not None:
                if self.sniffer.running:
                    self.sniffer.stop(join=False)
                self.sniffer.join()
            if self.pcap is not None:
                self.pcap.close()
            if self.output_file is not None:
                self.output_file.close()
            if self.socket is not None:
                self.socket.close()
        print(f"[EVA ACTIVE SUMMARY] events={dict(self.events)}")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--bob-public", required=True)
    parser.add_argument("--bob-fingerprint", required=True)
    parser.add_argument("--claimed-alice-fingerprint", required=True)
    parser.add_argument("--finish-mode", choices=("invalid-mac", "withhold"), default="invalid-mac")
    parser.add_argument("--attempts", type=int, default=300)
    parser.add_argument("--channel", type=int, default=5)
    parser.add_argument("--width", choices=("HT20", "HT40+", "HT40-"), default="HT20")
    parser.add_argument("--duration", type=float, default=900.0)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--response-timeout", type=float, default=4.0)
    parser.add_argument("--ack-timeout", type=float, default=4.0)
    parser.add_argument("--start-sequence", type=int, default=50000)
    parser.add_argument("--out", default="eva_attack_events.csv")
    parser.add_argument("--pcap", default="eva_attack.pcap")
    args = parser.parse_args()
    if not valid_hex_token(args.run_id, 16):
        parser.error("--run-id phải là 16 ký tự hex viết thường")
    if not valid_hex_token(args.claimed_alice_fingerprint.lower().replace(":", ""), 64):
        parser.error("claimed-alice-fingerprint phải là fingerprint SHA-256")
    args.claimed_alice_fingerprint = args.claimed_alice_fingerprint.lower().replace(":", "")
    if args.attempts < 1 or args.start_sequence < 0:
        parser.error("attempts phải dương và start-sequence không âm")
    for name in ("duration", "interval", "response_timeout", "ack_timeout"):
        value = getattr(args, name)
        if not math.isfinite(value) or value <= 0:
            parser.error(f"{name.replace('_', '-')} phải là số hữu hạn dương")
    return args


def main():
    try:
        ActiveEva(parse_args()).run()
    except (OSError, RuntimeError, ValueError, PermissionError) as error:
        sys.exit(f"[EVA ERROR] {error}")


if __name__ == "__main__":
    main()
