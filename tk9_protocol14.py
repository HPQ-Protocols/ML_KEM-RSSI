#!/usr/bin/env python3
"""Shared ML-KEM, transcript, RSSI-baseline, and 802.11 helpers for Lan 13."""

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import shutil
import statistics
import subprocess
import tempfile
from pathlib import Path

PROTOCOL = "TK12-MLKEM768-RSSI-1"
ETHER_TYPE = 0x88B5
KEM_NAME = "ML-KEM-768"
KEM_CIPHERTEXT_BYTES = 1088
KEM_SECRET_BYTES = 32


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def transcript_bytes(init_message, response_message):
    first = canonical_json(init_message)
    second = canonical_json(response_message)
    return len(first).to_bytes(4, "big") + first + len(second).to_bytes(4, "big") + second


def valid_hex_token(value, length):
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def make_finish_core(run_id, sequence, nonce_a, nonce_b, alice_rssi_ok):
    if not valid_hex_token(run_id, 16):
        raise ValueError("run_id phải là 16 ký tự hex viết thường")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ValueError("sequence phải là số nguyên không âm")
    if not valid_hex_token(nonce_a, 32) or not valid_hex_token(nonce_b, 32):
        raise ValueError("nonce FINISH phải gồm 32 ký tự hex viết thường")
    return {
        "protocol": PROTOCOL,
        "type": "FINISH",
        "run_id": run_id,
        "sequence": sequence,
        "nonce_a": nonce_a,
        "nonce_b": nonce_b,
        "alice_rssi_ok": alice_rssi_ok is True,
    }


def run_openssl(arguments, timeout=30):
    executable = shutil.which("openssl")
    if executable is None:
        raise RuntimeError("OpenSSL không có trong PATH; cần OpenSSL 3.5 trở lên có ML-KEM-768")
    try:
        result = subprocess.run(
            [executable, *map(str, arguments)],
            check=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("OpenSSL hết thời gian xử lý ML-KEM") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"OpenSSL thất bại: {detail or error.returncode}") from error
    return result.stdout


def require_mlkem():
    version = run_openssl(["version"]).decode("ascii", errors="replace").strip()
    algorithms = run_openssl(["list", "-kem-algorithms"]).decode("utf-8", errors="replace")
    if KEM_NAME not in algorithms and "MLKEM768" not in algorithms:
        raise RuntimeError(f"{version} không cung cấp {KEM_NAME}; cài OpenSSL có hỗ trợ ML-KEM-768")
    return version


def generate_identity(name, output_dir):
    if not name or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in name):
        raise ValueError("Tên identity chỉ được gồm chữ, số, gạch ngang hoặc gạch dưới")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    private_path = output / f"{name}_mlkem768_private.pem"
    public_path = output / f"{name}_mlkem768_public.pem"
    if private_path.exists() or public_path.exists():
        raise FileExistsError(f"Bộ khóa {name} đã tồn tại; không ghi đè khóa hiện có")
    require_mlkem()
    try:
        run_openssl(["genpkey", "-algorithm", KEM_NAME, "-out", private_path, "-outpubkey", public_path])
        if os.name != "nt":
            os.chmod(private_path, 0o600)
            os.chmod(public_path, 0o644)
        fingerprint = public_fingerprint(public_path)
    except Exception:
        private_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        raise
    return private_path, public_path, fingerprint


def public_der(public_path):
    return run_openssl(["pkey", "-pubin", "-in", public_path, "-outform", "DER"])


def public_fingerprint(public_path):
    return hashlib.sha256(public_der(public_path)).hexdigest()


def load_private_identity(private_path, public_path):
    private_file = Path(private_path)
    public_file = Path(public_path)
    if not private_file.is_file() or not public_file.is_file():
        raise FileNotFoundError("Cần cả private PEM cục bộ và public PEM tương ứng")
    if os.name != "nt" and private_file.stat().st_mode & 0o077:
        raise PermissionError(f"Quyền file private không an toàn: {private_file}; dùng chmod 600")
    require_mlkem()
    private_der = run_openssl(["pkey", "-in", private_file, "-pubout", "-outform", "DER"])
    if not hmac.compare_digest(hashlib.sha256(private_der).digest(), hashlib.sha256(public_der(public_file)).digest()):
        raise ValueError("Private key và public key local không phải cùng một cặp")
    return hashlib.sha256(private_der).hexdigest()


def validate_peer_key(public_path, expected_fingerprint):
    fingerprint = public_fingerprint(public_path)
    normalized = expected_fingerprint.strip().lower().replace(":", "")
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError("--peer-fingerprint phải là SHA-256 gồm 64 ký tự hex")
    if not hmac.compare_digest(fingerprint, normalized):
        raise ValueError(f"Fingerprint peer không khớp: nhận được {fingerprint}")
    return fingerprint


def kem_encapsulate(public_path):
    with tempfile.TemporaryDirectory(prefix="tk12-kem-") as directory:
        ciphertext_path = Path(directory) / "ciphertext.bin"
        secret_path = Path(directory) / "secret.bin"
        run_openssl([
            "pkeyutl", "-encap", "-pubin", "-inkey", public_path,
            "-out", ciphertext_path, "-secret", secret_path,
        ])
        ciphertext = ciphertext_path.read_bytes()
        secret = secret_path.read_bytes()
    if len(ciphertext) != KEM_CIPHERTEXT_BYTES or len(secret) != KEM_SECRET_BYTES:
        raise RuntimeError("OpenSSL trả về kích thước ML-KEM-768 không đúng")
    return ciphertext, secret


def kem_decapsulate(private_path, ciphertext):
    if len(ciphertext) != KEM_CIPHERTEXT_BYTES:
        raise ValueError("Ciphertext ML-KEM-768 sai kích thước")
    with tempfile.TemporaryDirectory(prefix="tk12-kem-") as directory:
        ciphertext_path = Path(directory) / "ciphertext.bin"
        secret_path = Path(directory) / "secret.bin"
        ciphertext_path.write_bytes(ciphertext)
        if os.name != "nt":
            os.chmod(ciphertext_path, 0o600)
        run_openssl([
            "pkeyutl", "-decap", "-inkey", private_path,
            "-in", ciphertext_path, "-secret", secret_path,
        ])
        secret = secret_path.read_bytes()
    if len(secret) != KEM_SECRET_BYTES:
        raise RuntimeError("OpenSSL trả về shared secret ML-KEM-768 sai kích thước")
    return secret


def b64encode(value):
    return base64.b64encode(value).decode("ascii")


def b64decode(value, expected_length):
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("Trường ciphertext không phải Base64 hợp lệ") from error
    if len(decoded) != expected_length:
        raise ValueError("Trường ciphertext có kích thước không hợp lệ")
    return decoded


def derive_session_key(secret_alice_to_bob, secret_bob_to_alice, transcript):
    if len(secret_alice_to_bob) != KEM_SECRET_BYTES or len(secret_bob_to_alice) != KEM_SECRET_BYTES:
        raise ValueError("Shared secret ML-KEM sai kích thước")
    input_key = secret_alice_to_bob + secret_bob_to_alice
    salt = hashlib.sha256(b"TK12-MLKEM768-RSSI-1|" + transcript).digest()
    prk = hmac.new(salt, input_key, hashlib.sha256).digest()
    return hmac.new(prk, b"Lan12 transcript key confirmation\x01", hashlib.sha256).digest()


def mac_hex(key, label, transcript):
    return hmac.new(key, label.encode("ascii") + b"|" + transcript, hashlib.sha256).hexdigest()


def verify_mac(key, label, transcript, supplied):
    return hmac.compare_digest(mac_hex(key, label, transcript), str(supplied).lower())


def encode_message(message):
    encoded = canonical_json(message)
    if len(encoded) > 1900:
        raise ValueError("Gói giao thức vượt giới hạn an toàn cho một khung 802.11")
    return encoded


def decode_message(packet):
    try:
        from scapy.all import Dot11, Raw
    except ImportError as error:
        raise RuntimeError("Thiếu Scapy; cài Scapy trên Ubuntu trước khi chạy radio scripts") from error
    if not packet.haslayer(Dot11) or not packet.haslayer(Raw):
        return None
    raw = bytes(packet[Raw].load)
    if not raw.startswith(b"TK12{"):
        return None
    try:
        message = json.loads(raw[4:].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(message, dict) or message.get("protocol") != PROTOCOL:
        return None
    return message


def make_frame(payload, source_mac, destination_mac="ff:ff:ff:ff:ff:ff"):
    try:
        from scapy.all import Dot11, LLC, SNAP, RadioTap, Raw
    except ImportError as error:
        raise RuntimeError("Thiếu Scapy; cài Scapy trên Ubuntu trước khi chạy radio scripts") from error
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, addr1=destination_mac, addr2=source_mac, addr3="02:00:00:00:00:00")
        / LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
        / SNAP(OUI=0, code=ETHER_TYPE)
        / Raw(load=b"TK12" + payload)
    )


def read_rssi(packet):
    try:
        from scapy.all import RadioTap
    except ImportError as error:
        raise RuntimeError("Thiếu Scapy") from error
    radiotap = packet.getlayer(RadioTap)
    value = getattr(radiotap, "dBm_AntSignal", None) if radiotap else None
    if value is None:
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def set_monitor_channel(interface, channel, width):
    if width not in {"HT20", "HT40+", "HT40-"}:
        raise ValueError("--width phải là HT20, HT40+ hoặc HT40-")
    if not 1 <= channel <= 196:
        raise ValueError("--channel nằm ngoài miền hợp lệ")
    info = subprocess.run(
        ["iw", "dev", interface, "info"],
        capture_output=True,
        text=True,
        check=False,
    )
    if info.returncode:
        detail = info.stderr.strip() or info.stdout.strip() or "không đọc được cấu hình interface"
        raise RuntimeError(f"Không kiểm tra được interface {interface}: {detail}")
    if not any(line.strip() == "type monitor" for line in info.stdout.splitlines()):
        raise RuntimeError(f"Interface {interface} chưa ở monitor mode; hãy bật monitor mode trước")
    result = subprocess.run(
        ["iw", "dev", interface, "set", "channel", str(channel), width],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "lệnh iw thất bại"
        raise RuntimeError(f"Không đặt được {interface} channel {channel} {width}: {detail}")


def create_baseline(path, own_fingerprint, peer_fingerprint, channel, width, samples):
    if len(samples) < 10:
        raise ValueError("Cần ít nhất 10 phiên xác thực thành công để lưu RSSI baseline")
    values = [float(value) for value in samples]
    if not all(math.isfinite(value) for value in values):
        raise ValueError("RSSI baseline chứa giá trị không hữu hạn")
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    data = {
        "protocol": PROTOCOL,
        "own_fingerprint": own_fingerprint,
        "peer_fingerprint": peer_fingerprint,
        "channel": channel,
        "width": width,
        "sample_count": len(values),
        "median_rssi_dbm": median,
        "mad_rssi_db": mad,
        "samples_rssi_dbm": values,
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(temporary, 0o600)
    temporary.replace(target)
    return data


def load_baseline(path, own_fingerprint, peer_fingerprint, channel, width):
    target = Path(path)
    data = json.loads(target.read_text(encoding="utf-8"))
    expected = {
        "protocol": PROTOCOL,
        "own_fingerprint": own_fingerprint,
        "peer_fingerprint": peer_fingerprint,
        "channel": channel,
        "width": width,
    }
    for name, value in expected.items():
        if data.get(name) != value:
            raise ValueError(f"RSSI baseline không khớp cấu hình ở trường {name}")
    sample_count = int(data.get("sample_count", 0))
    median = float(data.get("median_rssi_dbm"))
    if sample_count < 10 or not math.isfinite(median):
        raise ValueError("RSSI baseline thiếu mẫu hoặc chứa median không hợp lệ")
    return data


def rssi_within_baseline(value, baseline, tolerance_db):
    if value is None or not math.isfinite(float(tolerance_db)) or tolerance_db <= 0:
        return False
    return abs(float(value) - float(baseline["median_rssi_dbm"])) <= float(tolerance_db)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-identity", metavar="NAME", required=True)
    parser.add_argument("--out-dir", default=".")
    args = parser.parse_args()
    try:
        private_path, public_path, fingerprint = generate_identity(args.generate_identity, args.out_dir)
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(f"Private key: {private_path}")
    print(f"Public key:  {public_path}")
    print(f"Fingerprint (share over a trusted non-Wi-Fi channel): {fingerprint}")


if __name__ == "__main__":
    main()