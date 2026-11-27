# RSSI-Gated ML-KEM-768 Key Establishment

This repository accompanies the paper **“RSSI-Gated ML-KEM-768 Authenticated Key Establishment Without Digital Signatures: Design and Testbed Evaluation.”** It documents the protocol, the three-machine wireless evaluation, separate software/network benchmarks, and the analysis artifacts used for the manuscript. The source repository is [HPQ-Protocols/ML_KEM-RSSI](https://github.com/HPQ-Protocols/ML_KEM-RSSI).

This is a research prototype, not a production-ready secure channel. RSSI is a local admission-policy input; it is not a cryptographic secret, peer authenticator, or proof of physical distance.

## Protocol summary

Alice and Bob use long-term ML-KEM-768 key pairs. They verify each other's public-key fingerprints over an authenticated channel independent of Wi-Fi, perform reciprocal encapsulations, and derive a session key from both KEM shared secrets and a canonical handshake transcript. Role-separated HMAC tags provide explicit key confirmation. Each endpoint also checks its received RSSI against its own calibrated median with a configured 4 dB tolerance. Bob accepts only if the transcript confirmation and both endpoint gate decisions pass.

## Repository map

- `main.tex`, bibliography files, and `figures/`: manuscript source and its figures.
- `prism-uploads/thuc nghiem final/`: RF calibration/evaluation baselines, CSV logs, available PCAPs, and the log evaluator.
- `prism-uploads/do luong/Final/`: benchmark scripts, their archived summary/sample outputs, and figure-generation scripts.
- `figures/`: manuscript graphics, including benchmark and RSSI result plots.

The exact RF conditions are not fully recorded for every run (for example, adapter/antenna models and placements, driver versions, and complete environment metadata). The archived observations can be re-analyzed, but the RF environment cannot be bit-for-bit reproduced from the logs alone.

## Experimental workflow

### 1. Prepare the RF testbed

The reported RF evaluation used three laptop-class hosts: Alice, Bob, and Eve. Use Wi-Fi adapters and drivers that support monitor mode, raw IEEE 802.11 frame capture/transmission, and a Radiotap `dBm_AntSignal` RSSI value. The documented channel configuration is channel 5 / HT20. Keep all participating adapters on the same channel and bandwidth and record the host, adapter, antenna placement, driver, channel, bandwidth, location, and run ID.

The endpoint helper invokes OpenSSL for ML-KEM-768 operations; use an OpenSSL build that advertises ML-KEM-768. Scapy is used by the RF tools; Matplotlib is used for plots and the evaluator dashboard. The benchmark scripts additionally use `liboqs-python`; the TCP/netem benchmark requires Linux `tc`/`iproute2` and permission to configure the loopback qdisc.

Before transmitting, confirm that the equipment and frequency use are authorized. Enabling monitor mode or changing channels may interrupt ordinary Wi-Fi connectivity. Check the runtime before a run:

```sh
openssl version
openssl list -kem-algorithms
IFACE=wlan0mon  # replace with the monitor interface name
iw dev "$IFACE" info
```

Put each adapter into monitor mode using the procedure supported by its Linux driver, then confirm that the selected interface is in monitor mode, OpenSSL lists ML-KEM-768, and all nodes use the same channel/width. Generic interface-conversion commands can disconnect Wi-Fi or fail on a driver that lacks monitor support. Before a live run, check that the endpoint/helper versions match and that their imports and CLI help work. Keep each run's output in a new directory so the scripts cannot overwrite earlier logs.

### 2. Provision identities and baselines

1. Generate fresh ML-KEM-768 identity key pairs locally for Alice and Bob. Do not reuse old or distributed private keys.
2. Exchange each public key and its SHA-256 fingerprint over a trusted, authenticated non-Wi-Fi channel. Verify the received fingerprint independently and pin it before the experiment. Eve must not receive either endpoint's private key.
3. Run calibration with Alice and Bob only; Eve is not transmitting. Collect 50 successful handshakes per endpoint and save each endpoint's baseline separately. Only successful calibration samples contribute to the median.
4. Fix the RSSI tolerance at 4 dB before evaluation. The supplied baselines report median RSSI of -35 dBm at Alice and -27 dBm at Bob; the stored MAD is 0 dB at integer-dBm resolution. The tolerance is not derived from a validated tail model.

### 3. Run the distinct RF conditions

Use a new run ID for each condition and retain the complete CSV/PCAP outputs. Use the role scripts' `--help` output to map these steps to the exact command-line options in the checked-out release; do not reuse a run ID across calibration and evaluation.

1. **Calibration:** stop Eve. Start Bob's calibration/responder process, then Alice's calibration/initiator process with the same run ID, channel, and width. Collect 50 successful sessions at each endpoint, save separate baselines, and stop both endpoints after calibration. The supplied medians are -35 dBm at Alice and -27 dBm at Bob.
2. **Legitimate exchange and passive capture:** start Eve's passive capture process first, then Bob's evaluator/responder, then Alice's initiator. Stop the capture and endpoints after the scheduled run and allow logs/PCAPs to close. The supplied run contains 316 Alice INIT transmissions; Bob observed 313 unique sessions and recorded 291 authenticated decisions, 18 RSSI-gate rejections, and 4 FINISH timeouts. A passive capture contains handshake frames; it is not a key-recovery test.
3. **Active invalid-FINISH trials:** stop Alice and the passive listener. Start Bob's responder, then run Eve's active attacker with Bob's public key, Alice's claimed pinned fingerprint, and a fresh run ID. Eve initiates and sends a deliberately invalid FINISH MAC after an observed Bob response. The two near-labelled runs contain 120 Eva INIT attempts each; in the second run only 114 forged FINISH messages were sent after observed Bob responses. All 234 paired forged FINISH messages passed Bob's RSSI gate; 232 ended in explicit key-confirmation rejection and 2 timed out. A near/far label is not a calibrated distance measurement.
4. **FINISH-withheld control:** stop Alice and run Bob with Eve's attacker in FINISH-withheld mode under a new run ID. Eve sends INIT attempts but withholds FINISH. Bob observed 41 of 50 attempts and recorded a FINISH timeout for each observed session; the other 9 were not observed by Bob.
5. **Supplementary far-labelled runs:** preserve these as a separate condition. Their configuration/location metadata is incomplete, so do not pool them with the near-labelled trials or interpret the labels as a controlled distance sweep.

For every condition, stop processes cleanly, preserve Eva's sent-event records and Bob's receive/terminal records, and note any missing RSSI values or packet loss. Do not infer a Bob rejection from an Eva transmission that Bob did not observe.

### 4. Audit the logs

Join event and terminal records by `(run_id, nonce_a)`. Distinguish transmissions sent by Eva, messages observed by Bob, and Bob's terminal decisions. Do not count intermediate `PENDING_FINISH` rows as sessions. A sent INIT that Bob did not observe is not a Bob rejection; an observed session without a terminal decision is a timeout. Keep calibration records out of evaluation denominators.

The archived CSVs and `Evaluate_Security_Rigorous.py` are under `prism-uploads/thuc nghiem final/`. From the repository root, this command audits the supplied legitimate, near-labelled invalid-FINISH, and withholding Bob logs, joins the two near-run event logs, and creates a diagnostic dashboard:

```sh
python3 "prism-uploads/thuc nghiem final/Evaluate_Security_Rigorous.py" \
  --bob-rx "prism-uploads/thuc nghiem final/bob_legit.csv" \
    "prism-uploads/thuc nghiem final/bob_attack_near.csv" \
    "prism-uploads/thuc nghiem final/bob_attack_near6.csv" \
    "prism-uploads/thuc nghiem final/bob_withhold.csv" \
  --alice-tx "prism-uploads/thuc nghiem final/alice_legit_tx.csv" \
  --alice-rx "prism-uploads/thuc nghiem final/alice_legit_rx.csv" \
  --eva-tx "prism-uploads/thuc nghiem final/eva_forged_near_events.csv" \
    "prism-uploads/thuc nghiem final/eva_forged_near_events6.csv" \
  --bob-baseline "prism-uploads/thuc nghiem final/bob_baseline.json" \
  --alice-baseline "prism-uploads/thuc nghiem final/alice_baseline.json" \
  --plot-out "figures/rf-audit-dashboard.png"
```

For a different run set, inspect `--help`, pass every relevant file explicitly, and keep calibration rows out of evaluation inputs. Do not combine independent runs that reuse run IDs or duplicate the same events. The counts above are descriptive outcomes from a small number of runs. They are not generalized FAR/FRR estimates, independent Bernoulli trials, confidence bounds, or a zero false-accept probability.

## Separate benchmark workflow

These are complementary host-side experiments, not part of the raw 802.11 evaluation.

### In-process CPU and Monte Carlo

`benchmark_pq_local_RSSI.py` exercises three custom profiles: ML-KEM-768 plus ML-DSA-65, a synthetic two-KEM workload, and the proposed RSSI-gated profile. The recorded configuration uses 50 warmups and 1,000 measured samples per profile, recording process CPU time and profile byte counts. The proposed profile receives fixed RSSI test inputs equal to its configured baselines; no radio measurement occurs. Certificate-chain sizes are simulated byte overheads, not parsed or validated X.509 chains.

The same script produces an illustrative Monte Carlo model for the two comparison profiles only. It resamples measured CPU times and adds configured RTT multipliers, payload serialization delay, and exponential jitter for LAN, WAN, and constrained scenarios (10,000 samples per workload/scenario; seed 42 in the archived run). It does not model the proposed profile, RF behavior, packet loss, congestion, or retransmissions.

To rerun without overwriting the archived outputs, start in the repository root and use a separate output directory:

```sh
python3 "prism-uploads/do luong/Final/benchmark_pq_local_RSSI.py" \
  --warmup 50 --iterations 1000 \
  --simulation-iterations 10000 --seed 42 \
  --mldsa-cert-bytes 6600 --kemtls-cert-bytes 2400 \
  --output-dir "prism-uploads/do luong/Final/pq_local_benchmark_outputs-rerun"
```

### TCP loopback benchmark

`tcp_pq_benchmark_RSSI.py` measures 200 handshakes per profile/scenario after 15 warmups. It reports client-observed elapsed time and application-frame bytes for custom TLS-style, KEMTLS-style, and proposed-protocol scripts. Scenarios are unshaped localhost, LAN (100 Mbps / 2 ms RTT), WAN (10 Mbps / 40 ms RTT), and constrained loopback (256 kbps / 300 ms RTT). Linux `tc netem` shapes loopback traffic; the proposed script uses fixed RSSI inputs. This is not an over-the-air benchmark or a full implementation comparison against standardized TLS/KEMTLS.

Run with a separate output directory to preserve the archived data. Shaped cases require the privileges/tools noted above; inspect the script and ensure qdisc cleanup before running on a shared host.

```sh
python3 "prism-uploads/do luong/Final/tcp_pq_benchmark_RSSI.py" \
  --warmup 15 --iterations 200 \
  --mldsa-cert-bytes 6600 --kemtls-cert-bytes 2400 \
  --output-dir "prism-uploads/do luong/Final/tcp_pq_benchmark_outputs-rerun"
```

Both benchmark scripts accept additional parameters; run them with `--help` before changing certificate-byte assumptions, RSSI inputs, network profiles, or sample counts. Results will vary with the host, library build, and system load. Do not describe these scripted profiles as official TLS/KEMTLS measurements.

## Recreate every manuscript figure

The manuscript has five numbered figures. Figures 1 and 2 are TikZ drawings embedded in `main.tex`; Figures 3 and 4 are generated from archived benchmark summary CSVs; Figure 5 is generated from the RF baseline and paired evaluation CSVs.

### Figures 3 and 4: benchmark plots

The plotting script reads the archived summary CSVs from its current working directory and saves PNG/PDF files under `figures/`. Run it from its own directory:

```sh
cd "prism-uploads/do luong/Final"
python3 plot_paper_figures.py
cd ../../..
```

This creates:

- `figures/benchmark-payload.png` and `figures/benchmark-payload.pdf` (paper Figure 3: application-frame bytes and one-time credential key-generation CPU time).
- `figures/benchmark-latency.png` and `figures/benchmark-latency.pdf` (paper Figure 4: TCP loopback latency with 95% confidence intervals).

The script requires NumPy, pandas, and Matplotlib. It reads the archived summary CSVs; it does not rerun either benchmark. Its input/output directory constants are at the top of `plot_paper_figures.py`. To plot a fresh benchmark run, point those constants at the new summary-output directories first.

### Figure 5: wireless RSSI and outcomes

From the repository root:

```sh
python3 "prism-uploads/do luong/Final/plot_rssi_gate_behavior.py" \
  --data-dir "prism-uploads/thuc nghiem final" \
  --output-dir figures
```

This validates the expected terminal-outcome counts, pairs forged-FINISH events with Bob's records by `(run_id, nonce_a)`, and writes `figures/rssi-gate-behavior.png` and `figures/rssi-gate-behavior.pdf`. It uses the legitimate run and the two near-labelled invalid-MAC runs; it does not pool the supplementary far-labelled data.

### Figures 1 and 2 and the paper PDF

Compile the manuscript from the repository root with a LaTeX installation that includes the CAS class and bibliography dependencies:

```sh
latexmk -pdf -interaction=nonstopmode main.tex
```

Figure 1 (protocol message flow) and Figure 2 (experimental workflow) are TikZ source in `main.tex`; there are no separate image-generation commands for them. Tables 1–2 report the audited RF counts, while Tables 3–5 summarize the archived CPU, TCP, and Monte Carlo outputs. The table contents are typeset in `main.tex`; the plotting scripts do not generate the LaTeX tables automatically.

## Interpretation and limitations

- The identity trust anchor is the out-of-band-verified public-key fingerprint. RSSI does not authenticate a peer or replace key confirmation.
- The prototype uses long-term KEM identity keys and makes no forward-secrecy claim.
- The active trials test random invalid FINISH MACs. They do not test relay/distance bounding, adaptive transmit-power manipulation, a malicious peer holding a legitimately pinned key, key substitution during provisioning, or all replay/channel-manipulation cases.
- The game-based authentication statement is conditional on a mixed-secret KDF assumption; it is not an unconditional reduction from ML-KEM IND-CCA security for the supplied schedule.
- The current measurements do not establish embedded-device performance, energy/RAM use, general RF reproducibility, or deployment readiness.

## Data handling and safe use

Generate new keys for new experiments. Never commit private keys or include them in PCAPs/logs. Treat packet captures and radio logs as potentially identifying data; review and sanitize them before publication. Perform live RF tests only on authorized equipment and frequencies.

## Associated paper

Khiem Pham-Tuan, Minh Quang Le, and Khuong Nguyen-An, “RSSI-Gated ML-KEM-768 Authenticated Key Establishment Without Digital Signatures: Design and Testbed Evaluation.” Cite the final journal version and an immutable repository commit or release when available.