#!/usr/bin/env python3
"""Audit Lan 13 logs with observed-session denominators and no inferred FAR claims."""

import argparse
import csv
import json
import math
import statistics
import sys
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec


def read_rows(paths):
    rows = []
    for path in paths:
        with open(path, newline="", encoding="utf-8") as file_handle:
            rows.extend(csv.DictReader(file_handle))
    return rows


def sent_nonces(rows):
    keys = set()
    for row in rows:
        event = row.get("event", "")
        legacy_status = row.get("send_status", "")
        if (event == "INIT_SENT" or legacy_status.startswith("sent")) and row.get("nonce_a"):
            keys.add((row.get("run_id", ""), row["nonce_a"]))
    return keys


def final_sessions(rows):
    outcomes = {}
    observed = {}
    for row in rows:
        key = (row.get("run_id", ""), row.get("nonce_a", ""))
        if not key[1]:
            continue
        observed.setdefault(key, row)
        decision = row.get("decision", "")
        if decision and decision != "PENDING_FINISH":
            outcomes[key] = row
    return observed, outcomes


def event_keys(rows, event_name):
    return {
        (row.get("run_id", ""), row.get("nonce_a", ""))
        for row in rows
        if row.get("event") == event_name and row.get("nonce_a")
    }


def percent(numerator, denominator):
    return "n/a" if denominator == 0 else f"{100.0 * numerator / denominator:.2f}%"


def parse_float(value):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def load_baseline_median(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as file_handle:
        data = json.load(file_handle)
    median = parse_float(data.get("median_rssi_dbm"))
    if median is None or int(data.get("sample_count", 0)) < 10:
        raise ValueError(f"Baseline không hợp lệ hoặc thiếu mẫu: {path}")
    return median


def representative_sessions(rows):
    chosen = {}
    for row in rows:
        key = (row.get("run_id", ""), row.get("nonce_a", ""))
        if key[1] and key not in chosen:
            chosen[key] = row
    return chosen


def generate_dashboard(bob_rows, alice_tx_rows, alice_rx_rows, eva_tx_rows,
                       bob_baseline, alice_baseline, out_png):
    bob_observed, bob_final = final_sessions(bob_rows)
    alice_sent = sent_nonces(alice_tx_rows)
    eva_sent = sent_nonces(eva_tx_rows)
    alice_observed = alice_sent & bob_observed.keys()
    eva_observed = eva_sent & bob_observed.keys()
    alice_final = {key: bob_final[key] for key in alice_observed if key in bob_final}
    eva_final = {key: bob_final[key] for key in eva_observed if key in bob_final}
    session_rows = representative_sessions(bob_rows)

    fig = plt.figure(figsize=(15, 10), dpi=150)
    grid = gridspec.GridSpec(2, 2, hspace=0.38, wspace=0.27)

    ax = fig.add_subplot(grid[0, 0])
    t_values = [parse_float(row.get("rx_time_unix")) for row in session_rows.values()]
    valid_times = [value for value in t_values if value is not None]
    t0 = min(valid_times) if valid_times else 0.0
    for keys, color, marker, label in (
        (alice_observed, "#1f77b4", "o", "Alice sessions"),
        (eva_observed, "#d62728", "x", "Eva sessions"),
    ):
        points = []
        for key in keys:
            row = session_rows.get(key, {})
            rssi = parse_float(row.get("rssi_dbm"))
            timestamp = parse_float(row.get("rx_time_unix"))
            if rssi is not None:
                points.append((timestamp - t0 if timestamp is not None else len(points), rssi))
        if points:
            ax.scatter([point[0] for point in points], [point[1] for point in points],
                       color=color, marker=marker, alpha=0.75,
                       label=f"{label} (n={len(points)})")
    if bob_baseline is not None:
        ax.axhline(bob_baseline, color="#333333", linestyle="--",
                   label=f"Bob calibration median ({bob_baseline:.1f} dBm)")
    ax.set_title("Bob-side RSSI, one observation per session")
    ax.set_xlabel("Elapsed seconds (or ordered sample)")
    ax.set_ylabel("RSSI (dBm)")
    ax.grid(True, linestyle="--", alpha=0.35)
    if ax.has_data():
        ax.legend(fontsize=8)

    ax = fig.add_subplot(grid[0, 1])
    alice_rssi_rows = [
        (parse_float(row.get("rx_rssi_dbm")), row.get("status", ""))
        for row in alice_rx_rows
    ]
    for status, color in (("AUTHENTICATED", "#2ca02c"),
                          ("REJECTED_RSSI_GATE", "#ff7f0e")):
        values = [value for value, observed_status in alice_rssi_rows
                  if value is not None and observed_status == status]
        if values:
            ax.hist(values, bins=20, alpha=0.6, color=color, label=f"{status} (n={len(values)})")
    if alice_baseline is not None:
        ax.axvline(alice_baseline, color="#333333", linestyle="--",
                   label=f"Alice calibration median ({alice_baseline:.1f} dBm)")
    ax.set_title("Alice-side RESP RSSI; calibration reference only")
    ax.set_xlabel("RSSI at Alice (dBm)")
    ax.set_ylabel("Sessions")
    ax.grid(True, linestyle="--", alpha=0.35)
    if ax.has_data():
        ax.legend(fontsize=8)

    ax = fig.add_subplot(grid[1, 0])
    categories = ["INIT sent", "Bob observed", "Authenticated"]
    alice_counts = [
        len(alice_sent), len(alice_observed),
        sum(row.get("decision") == "AUTHENTICATED" for row in alice_final.values()),
    ]
    eva_counts = [
        len(eva_sent), len(eva_observed),
        sum(row.get("decision") == "AUTHENTICATED" for row in eva_final.values()),
    ]
    x_positions = list(range(len(categories)))
    bar_width = 0.36
    ax.bar([x - bar_width / 2 for x in x_positions], alice_counts, bar_width,
           label="Alice", color="#1f77b4")
    ax.bar([x + bar_width / 2 for x in x_positions], eva_counts, bar_width,
           label="Eva", color="#d62728")
    ax.set_xticks(x_positions, categories)
    ax.set_ylabel("Count")
    ax.set_title("Sent versus observed versus accepted (not an FAR estimate)")
    ax.grid(True, axis="y", linestyle="--", alpha=0.35)
    ax.legend(fontsize=8)

    ax = fig.add_subplot(grid[1, 1])
    decisions = sorted({row.get("decision", "") for row in bob_final.values() if row.get("decision")})
    x_positions = list(range(len(decisions)))
    alice_decisions = [sum(row.get("decision") == decision for row in alice_final.values())
                       for decision in decisions]
    eva_decisions = [sum(row.get("decision") == decision for row in eva_final.values())
                     for decision in decisions]
    ax.bar([x - bar_width / 2 for x in x_positions], alice_decisions, bar_width,
           label="Alice", color="#2ca02c")
    ax.bar([x + bar_width / 2 for x in x_positions], eva_decisions, bar_width,
           label="Eva", color="#ff7f0e")
    ax.set_xticks(x_positions, decisions, rotation=18, ha="right")
    ax.set_ylabel("Final observed sessions")
    ax.set_title("Bob final decisions; denominator is observed sessions")
    ax.grid(True, axis="y", linestyle="--", alpha=0.35)
    ax.legend(fontsize=8)

    run_ids = sorted({row.get("run_id", "") for row in bob_rows if row.get("run_id")})
    fig.suptitle(
        "Lan 13 evidence audit — observed outcomes only; no generalized FAR claim\n"
        f"run_id(s): {', '.join(run_ids) if run_ids else 'none'}",
        fontsize=12, fontweight="bold",
    )
    target = Path(out_png)
    target.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(target, dpi=170, bbox_inches="tight")
    plt.close(fig)
    print(f"Dashboard saved: {target}")


def report(bob_rows, alice_tx_rows, alice_rx_rows, eva_tx_rows, eva_rx_rows):
    evaluation_rows = [row for row in bob_rows if row.get("mode") == "evaluate"]
    bob_observed, bob_final = final_sessions(evaluation_rows)
    alice_sent = sent_nonces(alice_tx_rows)
    eva_sent = sent_nonces(eva_tx_rows)
    alice_observed = alice_sent & bob_observed.keys()
    eva_observed = eva_sent & bob_observed.keys()
    alice_final = {key: bob_final[key] for key in alice_observed if key in bob_final}
    eva_final = {key: bob_final[key] for key in eva_observed if key in bob_final}

    print("Lan 13 ML-KEM-768 + out-of-band key pinning + RSSI gate")
    print("Counts are descriptive for these logs; no generalized FAR/FRR is inferred.")
    print(f"Alice INIT sent: {len(alice_sent)}; observed by Bob: {len(alice_observed)}")
    print(
        f"Alice final at Bob: {dict(Counter(row.get('decision', '') for row in alice_final.values()))}; "
        f"accepted={sum(row.get('decision') == 'AUTHENTICATED' for row in alice_final.values())}/"
        f"{len(alice_observed)} observed ({percent(sum(row.get('decision') == 'AUTHENTICATED' for row in alice_final.values()), len(alice_observed))})"
    )
    print(f"Alice local statuses: {dict(Counter(row.get('status', '') for row in alice_rx_rows))}")
    print(f"Eva INIT sent: {len(eva_sent)}; observed by Bob: {len(eva_observed)}")
    print(
        f"Eva final at Bob: {dict(Counter(row.get('decision', '') for row in eva_final.values()))}; "
        f"accepted={sum(row.get('decision') == 'AUTHENTICATED' for row in eva_final.values())}/"
        f"{len(eva_observed)} observed ({percent(sum(row.get('decision') == 'AUTHENTICATED' for row in eva_final.values()), len(eva_observed))}); "
        f"sent denominator={len(eva_sent)}"
    )

    event_counts = Counter(row.get("event", "") for row in eva_tx_rows if row.get("event"))
    if event_counts:
        print(f"Eva active event log: {dict(event_counts)}")
        response_keys = event_keys(eva_tx_rows, "RESP_RECEIVED")
        forged_keys = event_keys(eva_tx_rows, "FORGED_FINISH_SENT")
        forged_observed = forged_keys & bob_observed.keys()
        forged_final = {key: bob_final[key] for key in forged_observed if key in bob_final}
        forged_decisions = Counter(row.get("decision", "") for row in forged_final.values())
        gate_pass = sum(str(row.get("rssi_ok", "")).lower() == "true" for row in forged_final.values())
        gate_fail = sum(str(row.get("rssi_ok", "")).lower() == "false" for row in forged_final.values())
        mac_reject_pass = sum(
            row.get("decision") == "REJECTED_ALICE_KEY_CONFIRMATION"
            and str(row.get("rssi_ok", "")).lower() == "true"
            for row in forged_final.values()
        )
        accepted_acks = sum(
            row.get("event") == "ACK_RECEIVED" and row.get("accepted", "").lower() == "true"
            for row in eva_tx_rows
        )
        print(
            f"Eva received Bob RESP: {len(response_keys)}/{len(eva_sent)} sent INITs; "
            f"forged FINISH sent: {len(forged_keys)}; Bob final outcome recorded for "
            f"{len(forged_final)}/{len(forged_keys)} forged FINISHs"
        )
        if forged_keys:
            print(
                f"Forged-FINISH Bob decisions (final outcomes only): {dict(forged_decisions)}; "
                f"RSSI gate pass/fail among these={gate_pass}/{gate_fail}; "
                f"invalid-MAC rejection despite RSSI pass={mac_reject_pass}/{gate_pass}"
            )
        print(f"Eva-observed accepted ACKs={accepted_acks}")
    if eva_rx_rows:
        passive_counts = Counter(row.get("frame_type", "") for row in eva_rx_rows)
        print(f"Passive-Eva parsed frames: {dict(passive_counts)}")
    print("Calibration rows are not pooled into evaluation denominators.")
    return evaluation_rows, alice_tx_rows, alice_rx_rows, eva_tx_rows

def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bob-rx", nargs="+", default=["bob_rx_log.csv"])
    parser.add_argument("--alice-tx", nargs="+", default=["alice_tx_log.csv"])
    parser.add_argument("--alice-rx", nargs="+", default=["alice_rx_log.csv"])
    parser.add_argument("--eva-tx", nargs="+", default=["eva_attack_events.csv"])
    parser.add_argument("--eva-rx", nargs="*", default=[])
    parser.add_argument("--bob-baseline")
    parser.add_argument("--alice-baseline")
    parser.add_argument("--plot-out", default="lan13_security_dashboard.png")
    parser.add_argument("--no-plot", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        bob_rows = read_rows(args.bob_rx)
        alice_tx_rows = read_rows(args.alice_tx)
        alice_rx_rows = read_rows(args.alice_rx)
        eva_tx_rows = read_rows(args.eva_tx)
        eva_rx_rows = read_rows(args.eva_rx)
        bob_baseline = load_baseline_median(args.bob_baseline)
        alice_baseline = load_baseline_median(args.alice_baseline)
    except (OSError, csv.Error, json.JSONDecodeError, ValueError) as error:
        sys.exit(f"[AUDIT ERROR] {error}")

    evaluation_rows, alice_tx_rows, alice_rx_rows, eva_tx_rows = report(
        bob_rows, alice_tx_rows, alice_rx_rows, eva_tx_rows, eva_rx_rows,
    )
    if args.no_plot:
        return
    if not evaluation_rows:
        print("[AUDIT WARNING] No Bob evaluation rows; dashboard skipped", file=sys.stderr)
        return
    generate_dashboard(
        evaluation_rows, alice_tx_rows, alice_rx_rows, eva_tx_rows,
        bob_baseline, alice_baseline, args.plot_out,
    )


if __name__ == "__main__":
    main()