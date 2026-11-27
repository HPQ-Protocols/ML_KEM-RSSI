#!/usr/bin/env python3
"""Plot Bob-side RSSI observations and paired ML-KEM session outcomes."""

import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt


SCRIPT_DIR = Path(__file__).parent
DEFAULT_DATA_DIR = SCRIPT_DIR / "../../thuc nghiem final"
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "../../../figures"
DATA_DIR = DEFAULT_DATA_DIR
OUTPUT_DIR = DEFAULT_OUTPUT_DIR
RSSI_TOLERANCE_DB = 4.0

COLORS = {
    "legitimate": "#4E79A7",
    "forged": "#F28E2B",
    "gate": "#59A14F",
    "timeout": "#9C9C9C",
}

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["Times New Roman", "DejaVu Serif"],
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.titleweight": "bold",
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 8.5,
        "axes.linewidth": 0.9,
        "grid.alpha": 0.3,
        "grid.linestyle": "--",
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
    }
)


def configure_paths():
    parser = argparse.ArgumentParser(
        description="Plot RSSI gate and key-confirmation testbed outcomes."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        help="directory containing bob_baseline.json and the experiment CSV files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="directory for the generated PNG and PDF figures",
    )
    args = parser.parse_args()

    if args.data_dir is not None:
        candidates = [args.data_dir.expanduser()]
    else:
        candidates = [
            DEFAULT_DATA_DIR,
            SCRIPT_DIR / "Thuc nghiem MLKEM-RSSI" / "results",
            SCRIPT_DIR / "results",
            Path.cwd() / "Thuc nghiem MLKEM-RSSI" / "results",
            Path.cwd() / "thuc nghiem final",
            Path.cwd() / "results",
        ]

    for candidate in candidates:
        candidate = candidate.expanduser()
        if (candidate / "bob_baseline.json").is_file():
            if args.output_dir is not None:
                output_dir = args.output_dir.expanduser()
            elif candidate == DEFAULT_DATA_DIR:
                output_dir = DEFAULT_OUTPUT_DIR
            else:
                output_dir = SCRIPT_DIR / "figures"
            return candidate, output_dir

    searched = "\n  - ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(
        "Could not locate bob_baseline.json. Set --data-dir to the folder that "
        "contains bob_baseline.json, bob_legit.csv, and the forged-event CSV files.\n"
        f"Searched:\n  - {searched}"
    )


def read_csv(filename):
    path = DATA_DIR / filename
    with path.open("r", newline="", encoding="utf-8-sig") as source:
        rows = list(csv.DictReader(source))
    if not rows:
        raise ValueError(f"No records found in {path}")
    return [{key: value.strip() for key, value in row.items()} for row in rows]


def terminal_bob_rows(filename):
    rows = [
        row
        for row in read_csv(filename)
        if row["decision"] not in ("", "PENDING_FINISH")
    ]
    keys = [(row["run_id"], row["nonce_a"]) for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError(f"Duplicate terminal Bob records in {filename}")

    for row in rows:
        row["rssi_dbm"] = float(row["rssi_dbm"])
        row["rssi_ok"] = row["rssi_ok"].lower() == "true"
    return rows


def paired_forged_rows(event_filename, bob_filename):
    events = read_csv(event_filename)
    sent_keys = [
        (row["run_id"], row["nonce_a"])
        for row in events
        if row["event"] == "FORGED_FINISH_SENT"
    ]
    if len(sent_keys) != len(set(sent_keys)):
        raise ValueError(f"Duplicate forged FINISH events in {event_filename}")

    bob_rows = terminal_bob_rows(bob_filename)
    bob_by_key = {(row["run_id"], row["nonce_a"]): row for row in bob_rows}
    unmatched = [key for key in sent_keys if key not in bob_by_key]
    if unmatched:
        raise ValueError(
            f"{len(unmatched)} forged FINISH events have no terminal Bob record "
            f"in {bob_filename}"
        )
    return [bob_by_key[key] for key in sent_keys]


def require_counts(rows, expected, description):
    actual = Counter(row["decision"] for row in rows)
    if len(rows) != sum(expected.values()) or actual != Counter(expected):
        raise ValueError(f"Unexpected {description} outcomes: {dict(actual)}")


def main():
    global DATA_DIR, OUTPUT_DIR
    DATA_DIR, OUTPUT_DIR = configure_paths()
    baseline_path = DATA_DIR / "bob_baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    bob_median = float(baseline["median_rssi_dbm"])
    lower_gate = bob_median - RSSI_TOLERANCE_DB
    upper_gate = bob_median + RSSI_TOLERANCE_DB

    legitimate = terminal_bob_rows("bob_legit.csv")
    forged = paired_forged_rows(
        "eva_forged_near_events.csv", "bob_attack_near.csv"
    ) + paired_forged_rows(
        "eva_forged_near_events6.csv", "bob_attack_near6.csv"
    )

    require_counts(
        legitimate,
        {
            "AUTHENTICATED": 291,
            "REJECTED_RSSI_GATE": 18,
            "REJECTED_FINISH_TIMEOUT": 4,
        },
        "legitimate-session",
    )
    require_counts(
        forged,
        {
            "REJECTED_ALICE_KEY_CONFIRMATION": 232,
            "REJECTED_FINISH_TIMEOUT": 2,
        },
        "paired forged-FINISH",
    )
    if not all(row["rssi_ok"] for row in forged):
        raise ValueError("A paired forged session did not pass Bob's RSSI gate")

    figure, (rssi_axis, outcome_axis) = plt.subplots(
        1,
        2,
        figsize=(12.0, 4.8),
        gridspec_kw={"width_ratios": [1.0, 1.25]},
    )

    all_rssi = [row["rssi_dbm"] for row in legitimate + forged]
    first_bin = math.floor(min(all_rssi)) - 0.5
    last_bin = math.ceil(max(all_rssi)) + 1.5
    bins = [first_bin + index for index in range(int(last_bin - first_bin) + 1)]

    rssi_axis.axvspan(
        lower_gate,
        upper_gate,
        color=COLORS["gate"],
        alpha=0.14,
        label=f"Bob gate-pass band ({lower_gate:.0f} to {upper_gate:.0f} dBm)",
    )
    rssi_axis.hist(
        [row["rssi_dbm"] for row in legitimate],
        bins=bins,
        histtype="step",
        linewidth=2.0,
        color=COLORS["legitimate"],
        label=f"Legitimate sessions (n={len(legitimate)})",
    )
    rssi_axis.hist(
        [row["rssi_dbm"] for row in forged],
        bins=bins,
        histtype="step",
        linewidth=2.0,
        color=COLORS["forged"],
        label=f"Paired forged-FINISH sessions (n={len(forged)})",
    )
    rssi_axis.axvline(
        bob_median,
        color="black",
        linestyle="--",
        linewidth=1.1,
        label=f"Bob calibration median ({bob_median:.0f} dBm)",
    )
    rssi_axis.set_xlabel("RSSI measured by Bob for the session INIT (dBm)")
    rssi_axis.set_ylabel("Unique sessions per 1-dB bin")
    rssi_axis.set_title("(a) RSSI observations and Bob's gate")
    rssi_axis.grid(axis="y")
    rssi_axis.spines["top"].set_visible(False)
    rssi_axis.spines["right"].set_visible(False)

    outcome_labels = [
        "Authenticated",
        "RSSI-gate rejected",
        "Key-confirmation rejected",
        "FINISH timeout",
    ]
    legitimate_counts = [291, 18, 0, 4]
    forged_counts = [0, 0, 232, 2]
    positions = list(range(len(outcome_labels)))
    bar_height = 0.34

    legitimate_bars = outcome_axis.barh(
        [position - bar_height / 2 for position in positions],
        legitimate_counts,
        bar_height,
        color=COLORS["legitimate"],
        label="Legitimate run",
    )
    forged_bars = outcome_axis.barh(
        [position + bar_height / 2 for position in positions],
        forged_counts,
        bar_height,
        color=COLORS["forged"],
        label="Forged-FINISH runs",
    )
    for bars in (legitimate_bars, forged_bars):
        for bar in bars:
            value = int(bar.get_width())
            outcome_axis.text(
                value + 3 if value else 3,
                bar.get_y() + bar.get_height() / 2,
                str(value),
                va="center",
                ha="left",
                fontsize=8.5,
            )

    outcome_axis.set_yticks(positions)
    outcome_axis.set_yticklabels(outcome_labels)
    outcome_axis.invert_yaxis()
    outcome_axis.set_xlim(0, 340)
    outcome_axis.set_xlabel("Unique sessions")
    outcome_axis.set_title("(b) Terminal outcomes by session type")
    outcome_axis.grid(axis="x")
    outcome_axis.spines["top"].set_visible(False)
    outcome_axis.spines["right"].set_visible(False)

    figure.suptitle(
        "RSSI admission and key-confirmation outcomes in the ML-KEM-768 testbed",
        fontsize=12,
        fontweight="bold",
        y=0.99,
    )
    rssi_handles, rssi_labels = rssi_axis.get_legend_handles_labels()
    figure.legend(
        rssi_handles,
        rssi_labels,
        loc="upper center",
        bbox_to_anchor=(0.27, 0.91),
        ncol=2,
        frameon=True,
        fontsize=7.5,
    )
    figure.legend(
        [legitimate_bars, forged_bars],
        ["Legitimate run", "Forged-FINISH runs"],
        loc="upper center",
        bbox_to_anchor=(0.77, 0.91),
        ncol=2,
        frameon=True,
        fontsize=8,
    )
    figure.text(
        0.5,
        0.055,
        "Bob's RSSI gate passed for all 234 paired forged sessions (run_id, nonce_a).",
        ha="center",
        fontsize=8,
    )
    figure.text(
        0.5,
        0.025,
        "Descriptive observations from supplied runs; not generalized FAR/FRR estimates.",
        ha="center",
        fontsize=8,
    )
    figure.tight_layout(rect=(0, 0.09, 1, 0.82))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    png_path = OUTPUT_DIR / "rssi-gate-behavior.png"
    pdf_path = OUTPUT_DIR / "rssi-gate-behavior.pdf"
    figure.savefig(png_path)
    figure.savefig(pdf_path)
    plt.close(figure)

    print(f"Saved: {png_path}")
    print(f"Saved: {pdf_path}")


if __name__ == "__main__":
    main()