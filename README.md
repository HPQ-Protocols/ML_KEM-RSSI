# RSSI-Gated ML-KEM-768 Key Establishment

This repository accompanies the paper **“RSSI-Gated ML-KEM-768 Authenticated Key Establishment Without Digital Signatures: Design and Testbed Evaluation.”** It contains the protocol implementation and analysis artifacts for a wireless testbed study combining ML-KEM-768, out-of-band public-key fingerprint pinning, transcript-bound HMAC key confirmation, and a local RSSI admission policy.

The project is a research prototype, not a production-ready secure channel. In particular, RSSI is not an authenticator, cryptographic secret, or proof of physical distance.

## Protocol at a glance

- Alice and Bob use long-term ML-KEM-768 key pairs. Each endpoint verifies the peer's public-key fingerprint over an authenticated channel independent of Wi-Fi.
- The endpoints perform reciprocal encapsulations, derive a session key from both KEM shared secrets and a canonical handshake transcript, and exchange role-separated HMAC confirmation tags.
- Each endpoint compares its received RSSI to its own calibrated median. The evaluated tolerance is 4 dB; Bob accepts only when key confirmation and both endpoint gate decisions pass.
- The reported three-machine experiment uses raw IEEE 802.11 monitor-mode frames. RSSI is read from received frames; separate software and TCP benchmarks do not measure radio RSSI.

## Repository contents

The project artifacts are organized by purpose:

- **Paper and figures:** `main.tex`, bibliography files, and the figures used by the manuscript.
- **Wireless experiment:** Alice, Bob, and Eve scripts; shared protocol helpers; event-log evaluator; calibration baselines; CSV logs; and available packet captures.
- **Benchmarking:** separate in-process CPU, TCP-loopback, and Monte Carlo scripts and their outputs. These workloads are custom profiles, not complete TLS or KEMTLS implementations.
- **RSSI result plot:** `plot_rssi_gate_behavior.py` and the input calibration/evaluation records used for Figure 5.

Use the supplied run-specific logs and metadata when reproducing published figures. Do not combine the supplementary far-labelled runs with the near-labelled results; their configuration metadata is incomplete.

## Recreate the RSSI results figure

The plot script requires Python 3 and Matplotlib. From the repository root, run:

```sh
python3 "prism-uploads/do luong/Final/plot_rssi_gate_behavior.py" \
  --data-dir "prism-uploads/thuc nghiem final" \
  --output-dir figures
```

The script checks the expected terminal-outcome counts, pairs forged-FINISH events with Bob's terminal records using `(run_id, nonce_a)`, and writes `rssi-gate-behavior.png` and `rssi-gate-behavior.pdf` to `figures/`. It uses Bob's calibration baseline and the legitimate run plus two near-labelled invalid-MAC runs. A count or pairing mismatch stops the script rather than silently producing a plot from different data.

## Reported wireless observations

The reported values are descriptive counts from the supplied testbed records, not population-level error-rate estimates:

| Observation | Result |
|---|---:|
| Successful calibration samples per endpoint | 50 |
| Alice / Bob median RSSI | -35 dBm / -27 dBm |
| Bob-observed legitimate sessions | 313 |
| Bob-authenticated / RSSI-gate rejected / FINISH timeout | 291 / 18 / 4 |
| Paired near-labelled forged FINISH sessions | 234 |
| Forged sessions passing Bob's RSSI gate | 234 |
| Key-confirmation rejections / timeouts / accepted | 232 / 2 / 0 |

The separate custom benchmarks report 0.152 ms mean process CPU time for the proposed in-process profile and 8.853 ms mean latency for its scripted TCP exchange under a configured 2 ms RTT scenario. The TCP gate uses configured RSSI test inputs, not measurements from a wireless interface. These measurements should not be interpreted as embedded-device performance or as a comparison against complete standardized TLS/KEMTLS implementations.

## Re-running the wireless experiment

A live RF run requires compatible Linux Wi-Fi adapters and drivers with monitor-mode and raw-frame support, permission to configure the interface and capture/transmit frames, and an OpenSSL build that provides ML-KEM-768. The exact Python dependencies depend on the endpoint/evaluator scripts; Scapy is used for 802.11 capture and Matplotlib for plots. Check the scripts' command-line help and the experiment runbook before operating the radios.

Before any new run:

1. Generate fresh endpoint key pairs locally. Exchange and verify public-key fingerprints over a trusted, non-Wi-Fi channel.
2. Keep private keys on their owning endpoint. Never commit private keys or include them in logs, packet captures, or analysis bundles.
3. Calibrate Alice and Bob independently using a separate calibration run. Record channel, bandwidth, hardware, antenna placement, driver, and environment; do not tune the threshold on the evaluation runs.
4. Use new run IDs and output filenames. Preserve the complete sent, observed, and terminal-outcome logs so packet loss and timeouts remain distinguishable from protocol rejections.
5. Operate only on equipment and frequencies for which you have authorization. Monitor mode and channel changes can interrupt ordinary Wi-Fi connectivity.

Packet captures and radio logs may contain device and environment metadata. Review and sanitize them before public release.

## Security scope and limitations

- The identity trust anchor is the out-of-band-verified public-key fingerprint. RSSI does not authenticate a peer and does not replace key confirmation.
- The current prototype uses long-term KEM identity keys and does not establish forward secrecy.
- The reported invalid-FINISH trials test random invalid MACs. They do not cover relay/distance bounding, adaptive transmit-power manipulation, a malicious peer with a legitimately pinned key, key-substitution during provisioning, or all replay and channel-manipulation cases.
- The observed zero acceptances in these logs is not a zero false-accept probability, a generalized FAR/FRR estimate, or a proof of security.
- CPU, TCP-loopback, and Monte Carlo outputs are separate from the raw 802.11 experiment. The Monte Carlo values are model outputs, not measured network latencies.

## Associated paper

Khiem Pham-Tuan, Minh Quang Le, and Khuong Nguyen-An, “RSSI-Gated ML-KEM-768 Authenticated Key Establishment Without Digital Signatures: Design and Testbed Evaluation.”

For publication, cite the final journal version and an immutable repository commit or release when available.