#!/usr/bin/env python3
"""Generate publication-ready figures (PNG 300 DPI & Vector PDF) for the RSSI-Gated ML-KEM-768 paper."""

from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Cấu hình chuẩn xuất bản IEEE / Elsevier
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 9.5,
    "axes.linewidth": 1.0,
    "grid.alpha": 0.35,
    "grid.linestyle": "--",
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})

# Đường dẫn tới thư mục kết quả thực nghiệm của bạn
LOCAL_DIR = Path("./pq_local_benchmark_outputs")
TCP_DIR = Path("./tcp_pq_benchmark_outputs")

df_tcp = pd.read_csv(TCP_DIR / "tcp_protocol_summary.csv")
df_rssi_tcp = pd.read_csv(TCP_DIR / "proposed_rssi_protocol_summary.csv")
df_local = pd.read_csv(LOCAL_DIR / "measured_handshake_summary.csv")
df_rssi_local = pd.read_csv(LOCAL_DIR / "proposed_rssi_protocol_summary.csv")

# Bảng màu học thuật (Okabe-Ito) & ký hiệu gạch chéo khi in đen trắng
BAR_COLORS = ["#4E79A7", "#F28E2B", "#2E8B57"]
BAR_HATCHES = ["//", "\\\\", ""]


def plot_figure_1():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 4.2))

    protocols = [
        "TLS 1.3\n(ML-KEM + ML-DSA)",
        "KEMTLS\n(ML-KEM-768)",
        "Proposed\n(RSSI-Gated ML-KEM)",
    ]
    wire_bytes = [
        df_tcp.loc[df_tcp["protocol"] == "TLS13_MLKEM768_MLDSA65", "wire_bytes"].iloc[0],
        df_tcp.loc[df_tcp["protocol"] == "KEMTLS_MLKEM768", "wire_bytes"].iloc[0],
        round(df_rssi_tcp["application_frame_bytes_mean"].iloc[0]),
    ]
    setup_ms = [
        df_local.loc[0, "setup_cpu_ms_once"],
        df_local.loc[1, "setup_cpu_ms_once"],
        df_rssi_local.loc[0, "setup_cpu_ms_once"],
    ]

    # Panel (a): Tổng dung lượng truyền tải bắt tay (Bytes)
    bars1 = ax1.bar(protocols, wire_bytes, color=BAR_COLORS, edgecolor="black", linewidth=0.9, width=0.55)
    for bar, h in zip(bars1, BAR_HATCHES):
        bar.set_hatch(h)
        yval = bar.get_height()
        ax1.text(
            bar.get_x() + bar.get_width() / 2.0,
            yval + 300,
            f"{int(yval):,} B",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=9.5,
        )

    pct_vs_tls = (1 - wire_bytes[2] / wire_bytes[0]) * 100
    pct_vs_kem = (1 - wire_bytes[2] / wire_bytes[1]) * 100
    ax1.annotate(
        f"-{pct_vs_tls:.1f}% vs TLS 1.3\n-{pct_vs_kem:.1f}% vs KEMTLS",
        xy=(2, wire_bytes[2]),
        xytext=(1.35, 9800),
        arrowprops=dict(arrowstyle="->", color="#2E8B57", lw=1.3),
        fontsize=9,
        fontweight="bold",
        color="#1B5E20",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#E8F5E9", edgecolor="#2E8B57", lw=0.8),
    )

    ax1.set_ylabel("Total Handshake Payload (Bytes)")
    ax1.set_title("(a) Handshake Communication Overhead")
    ax1.set_ylim(0, 16500)
    ax1.grid(axis="y")
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    # Panel (b): Chi phí khởi tạo khóa định danh (KeyGen Setup Time)
    bars2 = ax2.bar(protocols, setup_ms, color=BAR_COLORS, edgecolor="black", linewidth=0.9, width=0.55)
    for bar, h in zip(bars2, BAR_HATCHES):
        bar.set_hatch(h)
        yval = bar.get_height()
        ax2.text(
            bar.get_x() + bar.get_width() / 2.0,
            yval + 0.06,
            f"{yval:.3f} ms",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=9.5,
        )

    setup_red = (1 - setup_ms[2] / setup_ms[0]) * 100
    ax2.annotate(
        f"{setup_red:.1f}% faster setup\nthan ML-DSA-65",
        xy=(2, setup_ms[2]),
        xytext=(1.1, 1.45),
        arrowprops=dict(arrowstyle="->", color="#2E8B57", lw=1.3),
        fontsize=9,
        fontweight="bold",
        color="#1B5E20",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#E8F5E9", edgecolor="#2E8B57", lw=0.8),
    )

    ax2.set_ylabel("One-Time KeyGen CPU Time (ms)")
    ax2.set_title("(b) Endpoint Credential Provisioning Cost")
    ax2.set_ylim(0, 2.8)
    ax2.grid(axis="y")
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig("fig1_overhead_and_setup.png")
    fig.savefig("fig1_overhead_and_setup.pdf")
    plt.close(fig)


def plot_figure_2():
    fig, (ax_left, ax_right) = plt.subplots(
        1, 2, figsize=(11.0, 4.4), gridspec_kw={"width_ratios": [1.6, 1.0]}
    )

    def extract_series(sc_list):
        tls_m, tls_e, kem_m, kem_e, pro_m, pro_e = [], [], [], [], [], []
        for sc in sc_list:
            r_tls = df_tcp[(df_tcp["scenario"] == sc) & (df_tcp["protocol"] == "TLS13_MLKEM768_MLDSA65")].iloc[0]
            r_kem = df_tcp[(df_tcp["scenario"] == sc) & (df_tcp["protocol"] == "KEMTLS_MLKEM768")].iloc[0]
            r_pro = df_rssi_tcp[df_rssi_tcp["scenario"] == sc].iloc[0]
            tls_m.append(r_tls["mean_ms"])
            tls_e.append(r_tls["ci95_high_ms"] - r_tls["mean_ms"])
            kem_m.append(r_kem["mean_ms"])
            kem_e.append(r_kem["ci95_high_ms"] - r_kem["mean_ms"])
            pro_m.append(r_pro["mean_ms"])
            pro_e.append(r_pro["ci95_high_ms"] - r_pro["mean_ms"])
        return (tls_m, tls_e), (kem_m, kem_e), (pro_m, pro_e)

    # Panel (a): Localhost, LAN, WAN
    scenarios_left = ["Localhost_Unshaped", "LAN_100Mbps_2msRTT", "WAN_10Mbps_40msRTT"]
    labels_left = ["Localhost\n(Unshaped)", "LAN\n(100 Mbps, 2 ms RTT)", "WAN\n(10 Mbps, 40 ms RTT)"]
    (tls_l, tls_le), (kem_l, kem_le), (pro_l, pro_le) = extract_series(scenarios_left)

    x = np.arange(len(labels_left))
    w = 0.26
    b1 = ax_left.bar(
        x - w, tls_l, w, yerr=tls_le, capsize=3,
        label="TLS 1.3 (ML-KEM-768 + ML-DSA-65)", color=BAR_COLORS[0], edgecolor="black", linewidth=0.8, hatch="//"
    )
    b2 = ax_left.bar(
        x, kem_l, w, yerr=kem_le, capsize=3,
        label="KEMTLS (ML-KEM-768)", color=BAR_COLORS[1], edgecolor="black", linewidth=0.8, hatch="\\\\"
    )
    b3 = ax_left.bar(
        x + w, pro_l, w, yerr=pro_le, capsize=3,
        label="Proposed RSSI-Gated ML-KEM-768", color=BAR_COLORS[2], edgecolor="black", linewidth=0.8
    )

    for bars in (b1, b2, b3):
        for bar in bars:
            h = bar.get_height()
            ax_left.text(
                bar.get_x() + bar.get_width() / 2.0, h + 2.5, f"{h:.1f}",
                ha="center", va="bottom", fontsize=8.2, fontweight="bold"
            )

    ax_left.set_ylabel("Handshake Latency (ms) [Mean ± 95% CI]")
    ax_left.set_title("(a) Low-to-Moderate Latency Networks (TCP + netem)")
    ax_left.set_xticks(x)
    ax_left.set_xticklabels(labels_left)
    ax_left.set_ylim(0, 165)
    ax_left.legend(loc="upper left", frameon=True, facecolor="white", framealpha=0.9)
    ax_left.grid(axis="y")
    ax_left.spines["top"].set_visible(False)
    ax_left.spines["right"].set_visible(False)

    # Panel (b): Constrained IoT Link (256 kbps, 300 ms RTT)
    (tls_r, tls_re), (kem_r, kem_re), (pro_r, pro_re) = extract_series(["Constrained_256kbps_300msRTT"])
    x_r = np.arange(1)
    w_r = 0.22

    br1 = ax_right.bar(x_r - w_r * 1.2, tls_r, w_r, yerr=tls_re, capsize=4, color=BAR_COLORS[0], edgecolor="black", linewidth=0.8, hatch="//")
    br2 = ax_right.bar(x_r, kem_r, w_r, yerr=kem_re, capsize=4, color=BAR_COLORS[1], edgecolor="black", linewidth=0.8, hatch="\\\\")
    br3 = ax_right.bar(x_r + w_r * 1.2, pro_r, w_r, yerr=pro_re, capsize=4, color=BAR_COLORS[2], edgecolor="black", linewidth=0.8)

    for bar in (br1[0], br2[0], br3[0]):
        h = bar.get_height()
        ax_right.text(
            bar.get_x() + bar.get_width() / 2.0, h + 18, f"{h:.1f} ms",
            ha="center", va="bottom", fontsize=9, fontweight="bold"
        )

    diff_tls = tls_r[0] - pro_r[0]
    pct_tls = (diff_tls / tls_r[0]) * 100
    diff_kem = kem_r[0] - pro_r[0]
    pct_kem = (diff_kem / kem_r[0]) * 100

    ax_right.annotate(
        f"-{pct_tls:.1f}% vs TLS 1.3 (-{diff_tls:.1f} ms)\n-{pct_kem:.1f}% vs KEMTLS (-{diff_kem:.1f} ms)",
        xy=(w_r * 1.2, pro_r[0]),
        xytext=(-0.38, 1520),
        arrowprops=dict(arrowstyle="->", color="#2E8B57", lw=1.3),
        fontsize=8.8,
        fontweight="bold",
        color="#1B5E20",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="#E8F5E9", edgecolor="#2E8B57", lw=0.8),
    )

    ax_right.set_ylabel("Handshake Latency (ms) [Mean ± 95% CI]")
    ax_right.set_title("(b) Constrained IoT Link\n(256 kbps, 300 ms RTT)")
    ax_right.set_xticks(x_r)
    ax_right.set_xticklabels(["Constrained Wireless / IoT Link"])
    ax_right.set_ylim(0, 1750)
    ax_right.grid(axis="y")
    ax_right.spines["top"].set_visible(False)
    ax_right.spines["right"].set_visible(False)

    plt.tight_layout()
    fig.savefig("fig2_tcp_handshake_latency.png")
    fig.savefig("fig2_tcp_handshake_latency.pdf")
    plt.close(fig)


if __name__ == "__main__":
    plot_figure_1()
    plot_figure_2()
    print("Đã xuất thành công fig1_overhead_and_setup.(png/pdf) và fig2_tcp_handshake_latency.(png/pdf)")