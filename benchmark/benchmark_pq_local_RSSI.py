#!/usr/bin/env python3
"""Measure local PQ workloads, or delegate to the official KEMTLS experiment.

Profiles included:
- ML-KEM-768 + ML-DSA-65 with pre-provisioned signing credentials.
- A synthetic two-KEM workload; it is not a full KEMTLS state machine.
- The proposed RSSI-gated ML-KEM-768 protocol, with synthetic RSSI inputs.

Use --run-official-kemtls with --kemtls-repo to run the upstream Rustls KEMTLS
implementation and its measurement harness instead of these local profiles.
"""

import argparse
import base64
import csv
import hashlib
import hmac
import json
import math
import os
import platform
import random
import secrets
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


MLKEM_MLDSA = "ML-KEM-768 + ML-DSA-65 profile"
SYNTHETIC_TWO_KEM = "Synthetic two-KEM workload (KEM-auth)"
PROFILE_NAMES = (MLKEM_MLDSA, SYNTHETIC_TWO_KEM)
RSSI_GATED_PROFILE = "Proposed RSSI-gated ML-KEM-768 protocol"
RSSI_PROTOCOL_ID = "TK12-MLKEM768-RSSI-1"
DEFAULT_RSSI_BASELINES_DBM = {"alice": -35.0, "bob": -27.0}


PROFILE_DESCRIPTIONS = {
    MLKEM_MLDSA: (
        "One ephemeral ML-KEM-768 keygen/encap/decap, one ML-DSA-65 signature "
        "and verification, transcript hashing, and HKDF. Includes optional "
        "certificate chain size overhead."
    ),
    SYNTHETIC_TWO_KEM: (
        "Client/server two-KEM operation sequence using ML-KEM-768 (ephemeral + "
        "static server KEM key) with transcript hashing and HKDF."
    ),
}


def import_oqs():
    try:
        import oqs
    except ImportError as error:
        raise SystemExit(
            "Missing dependency: liboqs-python (import name 'oqs'). Install/configure "
            "it on WSL with ML-KEM-768 and ML-DSA-65 enabled, then rerun."
        ) from error
    return oqs


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(pseudorandom_key: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            pseudorandom_key, previous + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def framed_transcript(label: bytes, *parts: bytes):
    encoded = bytearray(label)
    for part in parts:
        encoded.extend(len(part).to_bytes(4, "big"))
        encoded.extend(part)
    return bytes(encoded), hashlib.sha256(encoded).digest()


def derive_single_kem_keys(shared_secret: bytes, transcript_hash: bytes):
    pseudorandom_key = hkdf_extract(transcript_hash, shared_secret)
    client_key = hkdf_expand(
        pseudorandom_key, b"local-benchmark/ML-KEM-ML-DSA/client-key" + transcript_hash, 32
    )
    server_key = hkdf_expand(
        pseudorandom_key, b"local-benchmark/ML-KEM-ML-DSA/server-key" + transcript_hash, 32
    )
    return client_key, server_key


def derive_two_kem_keys(ephemeral_secret: bytes, static_secret: bytes, transcript_hash: bytes):
    early_secret = hkdf_extract(transcript_hash, ephemeral_secret)
    handshake_secret = hkdf_extract(early_secret, static_secret)
    client_key = hkdf_expand(
        handshake_secret, b"local-benchmark/two-kem/client-key" + transcript_hash, 32
    )
    server_key = hkdf_expand(
        handshake_secret, b"local-benchmark/two-kem/server-key" + transcript_hash, 32
    )
    return client_key, server_key


def timed_setup(function):
    cpu_started = time.process_time_ns()
    wall_started = time.perf_counter_ns()
    value = function()
    return value, {
        "cpu_ms": (time.process_time_ns() - cpu_started) / 1_000_000,
        "wall_ms": (time.perf_counter_ns() - wall_started) / 1_000_000,
    }


def make_mlkem_mldsa_profile(oqs, cert_overhead_bytes: int = 0):
    client_kem = oqs.KeyEncapsulation("ML-KEM-768")
    server_kem = oqs.KeyEncapsulation("ML-KEM-768")
    signer = oqs.Signature("ML-DSA-65")
    verifier = oqs.Signature("ML-DSA-65")
    signer_public_key, signer_setup = timed_setup(signer.generate_keypair)

    def handshake(sequence: int):
        client_public_key = client_kem.generate_keypair()
        ciphertext, server_secret = server_kem.encap_secret(client_public_key)
        client_secret = client_kem.decap_secret(ciphertext)

        transcript, transcript_hash = framed_transcript(
            b"ML-KEM-768+ML-DSA-65 benchmark profile",
            sequence.to_bytes(8, "big"),
            client_public_key,
            ciphertext,
        )
        signature = signer.sign(transcript)
        signature_valid = verifier.verify(transcript, signature, signer_public_key)

        c_client_key, c_server_key = derive_single_kem_keys(client_secret, transcript_hash)
        s_client_key, s_server_key = derive_single_kem_keys(server_secret, transcript_hash)

        payload_bytes = (
            len(client_public_key)
            + len(ciphertext)
            + len(signature)
            + cert_overhead_bytes
        )
        is_valid = (
            client_secret == server_secret
            and signature_valid
            and c_client_key == s_client_key
            and c_server_key == s_server_key
        )
        return {
            "payload_bytes": payload_bytes,
            "valid": is_valid,
            "transcript_digest": transcript_hash,
        }

    return handshake, signer_setup, (client_kem, server_kem, signer, verifier)


def make_synthetic_two_kem_profile(oqs, cert_overhead_bytes: int = 0):
    client_kem = oqs.KeyEncapsulation("ML-KEM-768")
    server_ephemeral_kem = oqs.KeyEncapsulation("ML-KEM-768")
    server_static_kem = oqs.KeyEncapsulation("ML-KEM-768")
    server_static_public_key, static_setup = timed_setup(server_static_kem.generate_keypair)

    def handshake(sequence: int):
        # 1. Ephemeral Key Exchange (Server Auth / Forward Secrecy)
        client_ephemeral_public_key = client_kem.generate_keypair()
        ephemeral_ciphertext, server_ephemeral_secret = server_ephemeral_kem.encap_secret(
            client_ephemeral_public_key
        )
        client_ephemeral_secret = client_kem.decap_secret(ephemeral_ciphertext)

        # 2. Static KEM Authentication (Server Cert Public Key Encapsulation)
        static_ciphertext, client_static_secret = client_kem.encap_secret(
            server_static_public_key
        )
        server_static_secret = server_static_kem.decap_secret(static_ciphertext)

        transcript, transcript_hash = framed_transcript(
            b"synthetic two-KEM ML-KEM-768 workload",
            sequence.to_bytes(8, "big"),
            client_ephemeral_public_key,
            server_static_public_key,
            ephemeral_ciphertext,
            static_ciphertext,
        )

        # Fixed NameError & Tuple unpacking bug
        c_client_key, c_server_key = derive_two_kem_keys(
            client_ephemeral_secret, client_static_secret, transcript_hash
        )
        s_client_key, s_server_key = derive_two_kem_keys(
            server_ephemeral_secret, server_static_secret, transcript_hash
        )

        payload_bytes = (
            len(client_ephemeral_public_key)
            + len(ephemeral_ciphertext)
            + len(static_ciphertext)
            + cert_overhead_bytes
        )
        is_valid = (
            client_ephemeral_secret == server_ephemeral_secret
            and client_static_secret == server_static_secret
            and c_client_key == s_client_key
            and c_server_key == s_server_key
        )
        return {
            "payload_bytes": payload_bytes,
            "valid": is_valid,
            "transcript_digest": transcript_hash,
        }

    return handshake, static_setup, (client_kem, server_ephemeral_kem, server_static_kem)


def proposed_canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def proposed_encode_message(value):
    encoded = proposed_canonical_json(value)
    if len(encoded) > 1900:
        raise ValueError("Proposed protocol message exceeds the 802.11 payload limit")
    return encoded


def proposed_transcript(init_message, response_core):
    init_bytes = proposed_canonical_json(init_message)
    response_bytes = proposed_canonical_json(response_core)
    return len(init_bytes).to_bytes(4, "big") + init_bytes + len(response_bytes).to_bytes(4, "big") + response_bytes


def proposed_session_key(secret_alice_to_bob, secret_bob_to_alice, transcript):
    input_key = secret_alice_to_bob + secret_bob_to_alice
    salt = hashlib.sha256(RSSI_PROTOCOL_ID.encode("ascii") + b"|" + transcript).digest()
    pseudorandom_key = hmac.new(salt, input_key, hashlib.sha256).digest()
    return hmac.new(pseudorandom_key, b"Lan12 transcript key confirmation\x01", hashlib.sha256).digest()


def proposed_mac(key, label, transcript):
    return hmac.new(key, label.encode("ascii") + b"|" + transcript, hashlib.sha256).hexdigest()


def proposed_rssi_gate(observed_dbm, baseline_dbm, tolerance_db):
    return abs(observed_dbm - baseline_dbm) <= tolerance_db


def make_proposed_rssi_profile(oqs, arguments):
    alice_kem = oqs.KeyEncapsulation("ML-KEM-768")
    bob_kem = oqs.KeyEncapsulation("ML-KEM-768")
    bob_encapsulator = oqs.KeyEncapsulation("ML-KEM-768")
    (alice_public_key, bob_public_key), setup = timed_setup(
        lambda: (alice_kem.generate_keypair(), bob_kem.generate_keypair())
    )
    alice_fingerprint = hashlib.sha256(alice_public_key).hexdigest()
    bob_fingerprint = hashlib.sha256(bob_public_key).hexdigest()

    def handshake(sequence):
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
        init_payload = proposed_encode_message(init)

        secret_a_bob = bob_kem.decap_secret(ciphertext_a)
        ciphertext_b, secret_b_bob = bob_encapsulator.encap_secret(alice_public_key)
        bob_gate = proposed_rssi_gate(
            arguments.bob_rssi_dbm,
            arguments.bob_rssi_baseline_dbm,
            arguments.rssi_tolerance_db,
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
        bob_session_key = proposed_session_key(secret_a_bob, secret_b_bob, transcript)
        response = dict(response_core)
        response["mac_b"] = proposed_mac(bob_session_key, "BOB_RESP", transcript)
        response_payload = proposed_encode_message(response)

        secret_b_alice = alice_kem.decap_secret(ciphertext_b)
        alice_session_key = proposed_session_key(secret_a_alice, secret_b_alice, transcript)
        response_valid = (
            hmac.compare_digest(secret_a_alice, secret_a_bob)
            and hmac.compare_digest(secret_b_bob, secret_b_alice)
            and hmac.compare_digest(bob_session_key, alice_session_key)
            and hmac.compare_digest(
                proposed_mac(alice_session_key, "BOB_RESP", transcript), response["mac_b"]
            )
        )

        alice_gate = proposed_rssi_gate(
            arguments.alice_rssi_dbm,
            arguments.alice_rssi_baseline_dbm,
            arguments.rssi_tolerance_db,
        )
        finish_core = {
            "protocol": RSSI_PROTOCOL_ID,
            "type": "FINISH",
            "run_id": run_id,
            "sequence": sequence,
            "nonce_a": nonce_a,
            "nonce_b": nonce_b,
            "alice_rssi_ok": alice_gate,
        }
        finish_transcript = transcript + proposed_canonical_json(finish_core)
        finish = dict(finish_core)
        finish["mac_a"] = proposed_mac(alice_session_key, "ALICE_FINISH", finish_transcript)
        finish_payload = proposed_encode_message(finish)
        finish_valid = hmac.compare_digest(
            proposed_mac(bob_session_key, "ALICE_FINISH", finish_transcript), finish["mac_a"]
        )
        accepted = bool(finish_valid and alice_gate and bob_gate)

        ack = {
            "protocol": RSSI_PROTOCOL_ID,
            "type": "ACK",
            "run_id": run_id,
            "sequence": sequence,
            "nonce_a": nonce_a,
            "accepted": accepted,
        }
        ack_transcript = finish_transcript + str(accepted).lower().encode("ascii")
        ack["mac_b"] = proposed_mac(bob_session_key, "BOB_ACK", ack_transcript)
        ack_payload = proposed_encode_message(ack)
        ack_valid = hmac.compare_digest(
            proposed_mac(alice_session_key, "BOB_ACK", ack_transcript), ack["mac_b"]
        )

        return {
            "payload_bytes": sum(map(len, (init_payload, response_payload, finish_payload, ack_payload))),
            "valid": response_valid and finish_valid and ack_valid,
            "accepted": accepted,
            "alice_rssi_gate_pass": alice_gate,
            "bob_rssi_gate_pass": bob_gate,
            "transcript_digest": hashlib.sha256(transcript).hexdigest(),
        }

    return handshake, setup, (alice_kem, bob_kem, bob_encapsulator)


def summarize(values):
    if len(values) < 2:
        raise ValueError("At least two measurements are required for sample statistics")
    mean = statistics.mean(values)
    standard_deviation = statistics.stdev(values)
    margin = 1.96 * standard_deviation / math.sqrt(len(values))
    ordered = sorted(values)
    return {
        "n": len(values),
        "mean": mean,
        "mean_95ci_low_normal_approx": mean - margin,
        "mean_95ci_high_normal_approx": mean + margin,
        "sample_sd": standard_deviation,
        "median": statistics.median(values),
        "p95_nearest_rank": ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)],
        "min": min(values),
        "max": max(values),
    }


def parse_network(value):
    fields = value.split(",")
    if len(fields) != 6:
        raise argparse.ArgumentTypeError(
            "network must be NAME,BW_KBPS,RTT_MS,MLKEM_MLDSA_RTT_MULT,SYNTHETIC_TWO_KEM_RTT_MULT,JITTER_MEAN_MS"
        )
    name = fields[0].strip()
    try:
        bandwidth_kbps, rtt_ms, mldsa_rtts, kemtls_rtts, jitter_mean_ms = map(float, fields[1:])
    except ValueError as error:
        raise argparse.ArgumentTypeError("network numeric fields must be numbers") from error
    if not name or bandwidth_kbps <= 0 or min(rtt_ms, mldsa_rtts, kemtls_rtts, jitter_mean_ms) < 0:
        raise argparse.ArgumentTypeError("network values must be nonnegative; bandwidth must be positive")
    return {
        "name": name,
        "bandwidth_kbps": bandwidth_kbps,
        "rtt_ms": rtt_ms,
        "rtt_multipliers": {MLKEM_MLDSA: mldsa_rtts, SYNTHETIC_TWO_KEM: kemtls_rtts},
        "jitter_mean_ms": jitter_mean_ms,
    }


# Note: In standard TLS 1.3 vs KEMTLS (without cached certs), server-auth KEMTLS
# often requires 1.5 to 2 RTTs before client sends application data, whereas TLS 1.3 is 1-RTT.
DEFAULT_NETWORKS = (
    parse_network("Illustrative LAN,100000,2,1.0,1.5,0.2"),
    parse_network("Illustrative WAN,10000,40,1.0,1.5,5"),
    parse_network("Illustrative constrained link,256,300,1.0,1.5,30"),
)


def simulate_network(profile_samples, network, iterations, seed):
    random_state = random.Random(seed)
    summary_rows = []
    sample_rows = []
    for profile in PROFILE_NAMES:
        measured = [row for row in profile_samples if row["profile"] == profile]
        cpu_measurements = [row["cpu_ms"] for row in measured]
        payload_bytes = statistics.mean(row["payload_bytes"] for row in measured)
        multiplier = network["rtt_multipliers"][profile]
        transmission_ms = payload_bytes * 8 / network["bandwidth_kbps"]
        base_network_ms = network["rtt_ms"] * multiplier + transmission_ms
        latencies = []
        for iteration in range(1, iterations + 1):
            cpu_ms = random_state.choice(cpu_measurements)
            jitter_ms = (
                random_state.expovariate(1.0 / network["jitter_mean_ms"])
                if network["jitter_mean_ms"] > 0
                else 0.0
            )
            latency_ms = cpu_ms + base_network_ms + jitter_ms
            latencies.append(latency_ms)
            sample_rows.append({
                "network": network["name"],
                "iteration": iteration,
                "profile": profile,
                "cpu_ms_resampled_from_laptop": f"{cpu_ms:.9f}",
                "network_delay_ms_modeled": f"{base_network_ms + jitter_ms:.9f}",
                "modeled_latency_ms": f"{latency_ms:.9f}",
            })
        summary_rows.append({
            "network": network["name"],
            "profile": profile,
            "bandwidth_kbps": network["bandwidth_kbps"],
            "rtt_ms": network["rtt_ms"],
            "rtt_multiplier": multiplier,
            "jitter_mean_ms": network["jitter_mean_ms"],
            "payload_bytes_mean": payload_bytes,
            **summarize(latencies),
        })
    return summary_rows, sample_rows


def write_csv(path: Path, rows: list):
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_official_kemtls(arguments):
    repository = arguments.kemtls_repo.expanduser().resolve()
    experiment_script = repository / "measuring" / "scripts" / "experiment.py"
    if not experiment_script.is_file():
        raise SystemExit(
            f"Official KEMTLS experiment script not found: {experiment_script}. "
            "Use a complete checkout of thomwiggers/kemtls-experiment, including submodules."
        )

    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
        repository_commit = revision.stdout.strip() if revision.returncode == 0 else None
        branch_result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
        repository_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None
        changes_result = subprocess.run(
            ["git", "status", "--short"],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
        working_tree_changes = (
            changes_result.stdout.splitlines() if changes_result.returncode == 0 else None
        )
    except OSError:
        repository_commit = None
        repository_branch = None
        working_tree_changes = None

    started_at = datetime.now(timezone.utc)
    wall_started = time.perf_counter()
    command = [sys.executable, "scripts/experiment.py"]
    print("Running the upstream KEMTLS experiment harness with its native configuration.")
    completed = subprocess.run(
        command,
        cwd=repository / "measuring",
        env=os.environ.copy(),
        check=False,
    )
    elapsed_seconds = time.perf_counter() - wall_started

    output_directory = arguments.output_dir.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    metadata_path = output_directory / (
        "official_kemtls_run_" + started_at.strftime("%Y%m%dT%H%M%S.%fZ") + ".json"
    )
    metadata = {
        "experiment": "Official thomwiggers/kemtls-experiment measurement harness",
        "started_at_utc": started_at.isoformat(),
        "elapsed_seconds_for_entire_upstream_run": elapsed_seconds,
        "repository": str(repository),
        "repository_commit": repository_commit,
        "repository_branch": repository_branch,
        "working_tree_changes": working_tree_changes,
        "entrypoint": str(experiment_script.relative_to(repository)),
        "entrypoint_sha256": hashlib.sha256(experiment_script.read_bytes()).hexdigest(),
        "command": command,
        "machine_platform": platform.platform(),
        "is_wsl": "microsoft" in platform.uname().release.lower(),
        "machine_processor": platform.processor() or None,
        "logical_cpu_count": os.cpu_count(),
        "python_version": sys.version,
        "return_code": completed.returncode,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Run metadata: {metadata_path}")
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def run(arguments):
    oqs = import_oqs()
    output_directory = Path(arguments.output_dir).resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    profiles = {}
    resources = []
    setup_results = {}
    try:
        profiles[MLKEM_MLDSA], setup_results[MLKEM_MLDSA], resources_mldsa = (
            make_mlkem_mldsa_profile(oqs, arguments.mldsa_cert_bytes)
        )
        resources.extend(resources_mldsa)
        profiles[SYNTHETIC_TWO_KEM], setup_results[SYNTHETIC_TWO_KEM], resources_synthetic = (
            make_synthetic_two_kem_profile(oqs, arguments.kemtls_cert_bytes)
        )
        resources.extend(resources_synthetic)

        for profile in PROFILE_NAMES:
            for warmup_index in range(arguments.warmup):
                result = profiles[profile](warmup_index)
                if not result["valid"]:
                    raise RuntimeError(f"Correctness check failed during {profile} warm-up")

        sequence_order = [profile for _ in range(arguments.iterations) for profile in PROFILE_NAMES]
        random.Random(arguments.seed).shuffle(sequence_order)
        counters = {profile: 0 for profile in PROFILE_NAMES}
        sample_rows = []
        for profile in sequence_order:
            counters[profile] += 1
            cpu_started = time.process_time_ns()
            wall_started = time.perf_counter_ns()
            result = profiles[profile](counters[profile])
            wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
            cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
            if not result["valid"]:
                raise RuntimeError(f"Correctness check failed during {profile} sample {counters[profile]}")
            sample_rows.append({
                "profile": profile,
                "iteration": counters[profile],
                "cpu_ms": cpu_ms,
                "wall_ms": wall_ms,
                "payload_bytes": result["payload_bytes"],
            })

        summary_rows = []
        for profile in PROFILE_NAMES:
            rows = [row for row in sample_rows if row["profile"] == profile]
            cpu_stats = summarize([row["cpu_ms"] for row in rows])
            summary_rows.append({
                "profile": profile,
                "description": PROFILE_DESCRIPTIONS[profile],
                "payload_bytes": statistics.mean(row["payload_bytes"] for row in rows),
                "cpu_ms_mean": cpu_stats["mean"],
                "cpu_ms_sd": cpu_stats["sample_sd"],
                "cpu_ms_median": cpu_stats["median"],
                "cpu_ms_p95": cpu_stats["p95_nearest_rank"],
                "cpu_ms_95ci_low_normal_approx": cpu_stats["mean_95ci_low_normal_approx"],
                "cpu_ms_95ci_high_normal_approx": cpu_stats["mean_95ci_high_normal_approx"],
                "wall_ms_mean": statistics.mean(row["wall_ms"] for row in rows),
                "wall_ms_sd": statistics.stdev(row["wall_ms"] for row in rows),
                "n": len(rows),
                "setup_cpu_ms_once": setup_results[profile]["cpu_ms"],
                "setup_wall_ms_once": setup_results[profile]["wall_ms"],
            })

        proposed_handshake, proposed_setup, proposed_resources = make_proposed_rssi_profile(
            oqs, arguments
        )
        resources.extend(proposed_resources)
        for warmup_index in range(arguments.warmup):
            warmup_result = proposed_handshake(warmup_index)
            if not warmup_result["valid"]:
                raise RuntimeError("Proposed RSSI-gated protocol failed its warm-up check")

        proposed_sample_rows = []
        for iteration in range(1, arguments.iterations + 1):
            cpu_started = time.process_time_ns()
            wall_started = time.perf_counter_ns()
            result = proposed_handshake(iteration)
            wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
            cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
            if not result["valid"]:
                raise RuntimeError(f"Proposed RSSI-gated protocol failed at sample {iteration}")
            proposed_sample_rows.append({
                "protocol": RSSI_GATED_PROFILE,
                "iteration": iteration,
                "cpu_ms": cpu_ms,
                "wall_ms": wall_ms,
                "payload_bytes": result["payload_bytes"],
                "alice_rssi_gate_pass": result["alice_rssi_gate_pass"],
                "bob_rssi_gate_pass": result["bob_rssi_gate_pass"],
                "accepted": result["accepted"],
                "transcript_digest": result["transcript_digest"],
            })

        proposed_cpu_stats = summarize([row["cpu_ms"] for row in proposed_sample_rows])
        proposed_summary_rows = [{
            "protocol": RSSI_GATED_PROFILE,
            "description": "Proposed TK12 ML-KEM-768 reciprocal static-KEM, transcript-HMAC, and two-sided RSSI-gate profile; in-process simulation without radio transmission.",
            "payload_bytes_mean": statistics.mean(row["payload_bytes"] for row in proposed_sample_rows),
            "cpu_ms_mean": proposed_cpu_stats["mean"],
            "cpu_ms_sd": proposed_cpu_stats["sample_sd"],
            "cpu_ms_median": proposed_cpu_stats["median"],
            "cpu_ms_p95": proposed_cpu_stats["p95_nearest_rank"],
            "cpu_ms_95ci_low_normal_approx": proposed_cpu_stats["mean_95ci_low_normal_approx"],
            "cpu_ms_95ci_high_normal_approx": proposed_cpu_stats["mean_95ci_high_normal_approx"],
            "wall_ms_mean": statistics.mean(row["wall_ms"] for row in proposed_sample_rows),
            "wall_ms_sd": statistics.stdev(row["wall_ms"] for row in proposed_sample_rows),
            "n": len(proposed_sample_rows),
            "accepted_n": sum(row["accepted"] for row in proposed_sample_rows),
            "accepted_rate": statistics.mean(row["accepted"] for row in proposed_sample_rows),
            "alice_gate_pass_n": sum(row["alice_rssi_gate_pass"] for row in proposed_sample_rows),
            "bob_gate_pass_n": sum(row["bob_rssi_gate_pass"] for row in proposed_sample_rows),
            "setup_cpu_ms_once": proposed_setup["cpu_ms"],
            "setup_wall_ms_once": proposed_setup["wall_ms"],
        }]

        write_csv(output_directory / "measured_handshake_samples.csv", sample_rows)
        write_csv(output_directory / "measured_handshake_summary.csv", summary_rows)
        write_csv(output_directory / "proposed_rssi_protocol_samples.csv", proposed_sample_rows)
        write_csv(output_directory / "proposed_rssi_protocol_summary.csv", proposed_summary_rows)

        monte_carlo_rows = []
        monte_carlo_samples = []
        for network_index, network in enumerate(arguments.network):
            network_summary, network_samples = simulate_network(
                sample_rows,
                network,
                arguments.simulation_iterations,
                arguments.seed + network_index,
            )
            monte_carlo_rows.extend(network_summary)
            monte_carlo_samples.extend(network_samples)
        if arguments.network:
            write_csv(output_directory / "monte_carlo_summary.csv", monte_carlo_rows)
            write_csv(output_directory / "monte_carlo_latency_samples.csv", monte_carlo_samples)

        metadata = {
            "experiment": "Local Python/liboqs cryptographic workload measurement plus network Monte Carlo",
            "python_version": sys.version,
            "platform": platform.platform(),
            "is_wsl": "microsoft" in platform.uname().release.lower(),
            "liboqs_python_module": getattr(oqs, "__file__", None),
            "iterations_per_profile": arguments.iterations,
            "warmup_per_profile": arguments.warmup,
            "mldsa_cert_overhead_bytes": arguments.mldsa_cert_bytes,
            "kemtls_cert_overhead_bytes": arguments.kemtls_cert_bytes,
            "simulation_iterations_per_profile_network": arguments.simulation_iterations if arguments.network else 0,
            "seed": arguments.seed,
            "setup_timings": setup_results,
            "network_scenarios": arguments.network,
            "proposed_rssi_protocol": {
                "protocol_id": RSSI_PROTOCOL_ID,
                "implementation_scope": "In-process protocol-profile simulation with ML-KEM-768, canonical JSON transcript, role-separated HMACs, and no radio/network transmission.",
                "rssi_input_source": "Synthetic CLI values; not measured RSSI.",
                "alice_baseline_dbm": arguments.alice_rssi_baseline_dbm,
                "bob_baseline_dbm": arguments.bob_rssi_baseline_dbm,
                "alice_observed_dbm": arguments.alice_rssi_dbm,
                "bob_observed_dbm": arguments.bob_rssi_dbm,
                "tolerance_db": arguments.rssi_tolerance_db,
                "fingerprint_encoding": "SHA-256 of raw liboqs public-key bytes; pinned in-process for this benchmark profile.",
                "setup_timings": proposed_setup,
                "outputs": [
                    "proposed_rssi_protocol_samples.csv",
                    "proposed_rssi_protocol_summary.csv",
                ],
            },
        }
        (output_directory / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )

        print(f"Measured {arguments.iterations:,} handshakes per profile after {arguments.warmup} warmups")
        for row in summary_rows:
            print(
                f"{row['profile']}: Payload={row['payload_bytes']:.0f} B | "
                f"CPU mean={row['cpu_ms_mean']:.4f} ms, p95={row['cpu_ms_p95']:.4f} ms"
            )
        proposed_row = proposed_summary_rows[0]
        print(
            f"{RSSI_GATED_PROFILE}: CPU mean={proposed_row['cpu_ms_mean']:.4f} ms, "
            f"p95={proposed_row['cpu_ms_p95']:.4f} ms, "
            f"accepted={proposed_row['accepted_n']}/{proposed_row['n']} "
            "(RSSI inputs are synthetic)"
        )
        print(f"Outputs saved to: {output_directory}")
    finally:
        for resource in resources:
            free = getattr(resource, "free", None)
            if free is not None:
                free()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-official-kemtls",
        action="store_true",
        help="Run the upstream Rustls KEMTLS measurement harness instead of local profiles",
    )
    parser.add_argument(
        "--kemtls-repo",
        type=Path,
        help="Path to a complete thomwiggers/kemtls-experiment checkout",
    )
    parser.add_argument("--iterations", type=int, default=1000, help="Measured samples per profile")
    parser.add_argument("--warmup", type=int, default=50, help="Discarded sessions per profile")
    parser.add_argument("--simulation-iterations", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--mldsa-cert-bytes",
        type=int,
        default=0,
        help="Optional simulated certificate chain size in bytes for ML-DSA profile (e.g., 5500)",
    )
    parser.add_argument(
        "--kemtls-cert-bytes",
        type=int,
        default=0,
        help="Optional simulated certificate chain size in bytes for KEMTLS profile (e.g., 2500)",
    )
    parser.add_argument(
        "--network",
        action="append",
        type=parse_network,
        default=None,
        metavar="NAME,BW_KBPS,RTT_MS,MLDSA_RTT_MULT,SYNTHETIC_TWO_KEM_RTT_MULT,JITTER_MEAN_MS",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent / "pq_local_benchmark_outputs",
    )
    parser.add_argument("--alice-rssi-baseline-dbm", type=float, default=DEFAULT_RSSI_BASELINES_DBM["alice"])
    parser.add_argument("--bob-rssi-baseline-dbm", type=float, default=DEFAULT_RSSI_BASELINES_DBM["bob"])
    parser.add_argument("--alice-rssi-dbm", type=float, default=DEFAULT_RSSI_BASELINES_DBM["alice"])
    parser.add_argument("--bob-rssi-dbm", type=float, default=DEFAULT_RSSI_BASELINES_DBM["bob"])
    parser.add_argument("--rssi-tolerance-db", type=float, default=4.0)
    arguments = parser.parse_args()
    if arguments.run_official_kemtls:
        if arguments.kemtls_repo is None:
            parser.error("--run-official-kemtls requires --kemtls-repo")
        run_official_kemtls(arguments)
        return
    if arguments.kemtls_repo is not None:
        parser.error("--kemtls-repo requires --run-official-kemtls")
    if arguments.network is None:
        arguments.network = list(DEFAULT_NETWORKS)
    if arguments.iterations < 2:
        parser.error("--iterations must be at least 2")
    if arguments.warmup < 0 or arguments.simulation_iterations < 2:
        parser.error("--warmup must be nonnegative and --simulation-iterations at least 2")
    if arguments.rssi_tolerance_db <= 0 or not all(math.isfinite(value) for value in (
        arguments.alice_rssi_baseline_dbm,
        arguments.bob_rssi_baseline_dbm,
        arguments.alice_rssi_dbm,
        arguments.bob_rssi_dbm,
        arguments.rssi_tolerance_db,
    )):
        parser.error("RSSI baselines/readings must be finite and tolerance must be positive")
    run(arguments)


if __name__ == "__main__":
    main()