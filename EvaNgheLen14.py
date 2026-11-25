#!/usr/bin/env python3
"""Passive 802.11 capture and protocol-frame logger for the controlled experiment."""

import argparse
import csv
import hashlib
import math
import sys
import time
from collections import Counter

try:
    from scapy.all import PcapWriter, sniff
except ImportError as error:
    raise SystemExit("[EVA LISTEN ERROR] Scapy thiếu; cài Scapy trên Ubuntu.") from error

from tk9_protocol14 import decode_message, read_rssi, set_monitor_channel, valid_hex_token


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface")
    parser.add_argument("--run-id", help="Chỉ ghi protocol frame của run-id này; PCAP vẫn giữ mọi frame")
    parser.add_argument("--channel", type=int, default=5)
    parser.add_argument("--width", choices=("HT20", "HT40+", "HT40-"), default="HT20")
    parser.add_argument("--duration", type=float, default=300.0)
    parser.add_argument("--out", default="eva_rx_log.csv")
    parser.add_argument("--pcap", default="eva_raw.pcap")
    args = parser.parse_args()
    if args.run_id is not None and not valid_hex_token(args.run_id, 16):
        parser.error("--run-id phải là 16 ký tự hex viết thường")
    if not math.isfinite(args.duration) or args.duration <= 0:
        parser.error("duration phải là số hữu hạn dương")
    return args


def main():
    args = parse_args()
    try:
        set_monitor_channel(args.interface, args.channel, args.width)
        pcap = PcapWriter(args.pcap, append=False, sync=True)
        output_file = open(args.out, "w", newline="", encoding="utf-8")
    except (OSError, RuntimeError, ValueError) as error:
        sys.exit(f"[EVA LISTEN ERROR] {error}")

    writer = csv.writer(output_file)
    writer.writerow([
        "rx_time_unix", "source_mac", "frame_type", "protocol", "run_id",
        "sequence", "nonce_a", "nonce_b", "claimed_fingerprint",
        "rssi_dbm", "payload_sha256",
    ])
    output_file.flush()
    counts = Counter()

    def callback(packet):
        pcap.write(packet)
        message = decode_message(packet)
        if not message:
            return
        if args.run_id and message.get("run_id") != args.run_id:
            return
        source_mac = (packet["Dot11"].addr2 or "").lower()
        fingerprint = (
            message.get("alice_fingerprint")
            or message.get("bob_fingerprint")
            or ""
        )
        raw = bytes(packet["Raw"].load)
        writer.writerow([
            f"{time.time():.6f}", source_mac, message.get("type", ""),
            message.get("protocol", ""), message.get("run_id", ""),
            message.get("sequence", ""), message.get("nonce_a", ""),
            message.get("nonce_b", ""), fingerprint, read_rssi(packet),
            hashlib.sha256(raw).hexdigest(),
        ])
        output_file.flush()
        counts[message.get("type", "unknown")] += 1

    print(
        f"[EVA PASSIVE] listening on {args.interface}, channel {args.channel} "
        f"{args.width}, run_id={args.run_id or 'all'}"
    )
    try:
        sniff(iface=args.interface, prn=callback, store=False, timeout=args.duration)
    except KeyboardInterrupt:
        print("\n[EVA PASSIVE] Interrupted")
    finally:
        pcap.close()
        output_file.close()
    print(f"[EVA PASSIVE SUMMARY] protocol_frames={dict(counts)}")


if __name__ == "__main__":
    main()
