"""Shared helpers: key files, ECDH secret derivation, and a redacting logger."""
import json
import logging
import os
import platform
import re
import socket
import sys
import time
import traceback
from base64 import b64decode
from datetime import datetime
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parent
KEYS_DIR = ROOT / "keys"
LOGS_DIR = ROOT / "logs"
SESSION_FILE = KEYS_DIR / "session.json"
HOME = str(Path(os.environ.get("SUDO_USER") and f"~{os.environ['SUDO_USER']}" or "~").expanduser())


# Public protocol UUIDs (safe to show); any other UUID in a log is masked.
PUBLIC_UUIDS = {
    "72cddca3-ab00-4e94-bae5-868f93f8c6c0", "1eb74dc8-3c1c-45ab-9254-9f41596cd4d6",
    "0823da14-040b-4914-bf7c-450afa2850da", "29919a3c-a697-4a6f-bd3b-d14860cc9bce",
    "9a69aeff-e3fe-4e79-bb7d-5ae12272fd14", "5eaa65c0-57ee-4cf4-a3d5-a4aae20cbb0b",
}
UUID_PATTERN = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")


def _is_public_uuid(value):
    value = value.lower()
    return value in PUBLIC_UUIDS or value.endswith("-0000-1000-8000-00805f9b34fb")


# bleak's macOS scan lines carry nearby devices' names; replaced by per-run pseudonyms.
DEVICE_LINE = re.compile(r"(Discovered device \S+: )(.*?)( @ RSSI)")
# Library debug lines that add nothing over our own (GATT discovery chatter, bare callbacks).
NOISE = re.compile(r"^(Retrieving (descriptors|characteristics)|Descriptor discovered|"
                   r"peripheral_didDiscover|\w+_$|CentralManagerDelegate at |Write Characteristic )")


# Redacted by pattern even when we don't know the value (library debug output, errors).
PATTERNS = [
    (re.compile(r"""\bb(['"])(?:\\.|(?!\1).)*\1"""), "bytes"),  # raw bytes reprs (bleak debug)
    (re.compile(r"(Rivian Key )\w+"), r"\1<vin-suffix>"),          # vehicle's BLE name ends in VIN digits
    (re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+"), "email"),
    (re.compile(r"\b(?!00(?::00){5}\b)[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b"), "bt-address"),
    (re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?:_[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f])"), "bt-address"),  # BlueZ dev_XX_XX…
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "vin"),
    (re.compile(r"(?i)\b(u-sess|a-sess|csrf-token|authorization)(['\"]?\s*[:=]\s*['\"]?)[^'\",\s}]+"), r"\1\2<redacted>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "private_key"),
    # Rivian API JSON (error dumps): blank every identifying field's value
    (re.compile(r"""(?i)(['"](?:firstName|lastName|name|deviceName|shortName|hrid|email|vin|publicKey|"""
                r"""vehiclePublicKey|phonePublicKey|vasVehicleId|vasPhoneId|cccVehicleId|identityId|"""
                r"""mappedIdentityId|userId|id|inviteId|cccKeyId|deviceId)['"]\s*:\s*)(?:'[^']*'|"[^"]*")"""),
     r"\1'<redacted>'"),
]
# Generic shapes, applied after known values so those keep their specific <labels>.
LATE_PATTERNS = [
    (re.compile(r"\b04[0-9a-fA-F]{128}\b"), "public-key"),
    (re.compile(r"\b[0-9a-fA-F]{32}\b"), "hex-id"),
]


class Log:
    """Short progress lines on screen; a detailed debug log in logs/ for troubleshooting.

    Everything written to the debug log (our lines, library/bleak debug output, tracebacks) is
    redacted: values registered with `secret()` become <label>, and emails, Bluetooth
    addresses, VINs, auth headers and PEM keys are masked by pattern. The log is meant to be
    attached to a GitHub issue.
    """

    def __init__(self):
        self.secrets = {}
        self.file = None
        self.pseudonyms = {}  # same masked thing -> same <label#n> within a run (no reversal)

    def _pseudonym(self, kind, value):
        key = (kind, value.lower())
        if key not in self.pseudonyms:
            self.pseudonyms[key] = sum(1 for k in self.pseudonyms if k[0] == kind) + 1
        return f"<{kind}#{self.pseudonyms[key]}>"

    def _device_name(self, match):
        name = match.group(2)
        if name.startswith("Rivian Key") or name.startswith("<"):
            return match.group(0)  # the vehicle (already masked) or no name
        return match.group(1) + self._pseudonym("device-name", name) + match.group(3)

    def secret(self, value, label, whole_word=False):
        """Redact `value` as <label>. whole_word=True is for names: matched as whole words, and
        left visible on screen (it's the user's own name for things) but redacted in the log."""
        if not value:
            return
        if whole_word:  # names: don't blank out every occurrence of an ordinary word
            if len(str(value)) >= 4:
                self.secrets[rf"(?<!\w){re.escape(str(value))}(?!\w)"] = (label, True)
            return
        value = str(value)
        variants = {value}
        try:
            uuid = UUID(value)
            variants |= {str(uuid), uuid.hex}
        except ValueError:
            pass
        for variant in variants:
            if len(variant) >= 5:
                self.secrets[re.escape(variant)] = (label, False)

    def redact(self, text, screen=False):
        text = text.replace(HOME, "~")
        for pattern, label in PATTERNS:
            text = pattern.sub(label if "\\" in label else f"<{label}>", text)
        text = DEVICE_LINE.sub(self._device_name, text)
        for pattern, (label, is_name) in sorted(self.secrets.items(), key=lambda kv: -len(kv[0])):
            if not (screen and is_name):
                text = re.sub(pattern, f"<{label}>", text, flags=re.IGNORECASE)
        for pattern, label in LATE_PATTERNS:
            text = pattern.sub(f"<{label}>", text)
        return UUID_PATTERN.sub(
            lambda m: m.group(0) if _is_public_uuid(m.group(0)) else self._pseudonym("uuid", m.group(0)), text)

    def open(self, name):
        """Start the debug log for this run and route all Python logging (bleak etc.) into it."""
        LOGS_DIR.mkdir(exist_ok=True)
        path = LOGS_DIR / f"{name}-{time.strftime('%Y%m%d-%H%M%S')}.log"
        self.file = open(path, "w")
        give_back_to_sudo_user(LOGS_DIR, path)
        handler = logging.StreamHandler(self.file)
        handler.setFormatter(_RedactingFormatter(self))
        handler.addFilter(lambda record: not NOISE.match(record.getMessage()))
        root = logging.getLogger()
        root.handlers[:] = [handler]
        root.setLevel(logging.DEBUG)
        logging.getLogger("asyncio").setLevel(logging.WARNING)
        # Dumps every nearby device (names, addresses) at startup: never useful, never safe.
        logging.getLogger("bleak.backends.bluezdbus.manager").setLevel(logging.INFO)
        logging.getLogger("rivian").setLevel(logging.ERROR)  # its warnings dump whole API responses
        self.secret(socket.gethostname().split(".")[0], "hostname", whole_word=True)
        self.debug(f"{name} started: {environment()}")
        return path

    def _write(self, level, message):
        if self.file:
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            self.file.write(self.redact(f"{stamp} {level:5} {message}") + "\n")
            self.file.flush()

    def __call__(self, message):
        """Progress line: screen + debug log."""
        print(self.redact(f"[{time.strftime('%H:%M:%S')}] {message}", screen=True), flush=True)
        self._write("INFO", message)

    def debug(self, message):
        """Detail for troubleshooting: debug log only."""
        self._write("DEBUG", message)

    def exception(self, message):
        """Failure with traceback: one line on screen, traceback in the debug log."""
        self(message)
        # Frames only — no exception message (API errors embed whole responses).
        error = sys.exc_info()[1]
        frames = "".join(traceback.format_tb(error.__traceback__)) if error else ""
        self._write("ERROR", f"{type(error).__name__ if error else 'error'} at:\n{frames}")


class _RedactingFormatter(logging.Formatter):
    def __init__(self, log_):
        super().__init__("%(asctime)s.%(msecs)03d %(levelname)-5s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        self.log = log_

    def format(self, record):
        return self.log.redact(super().format(record))


def environment():
    """Versions and platform, to help diagnose tester reports (nothing identifying)."""
    from importlib.metadata import PackageNotFoundError, version
    parts = [f"python {platform.python_version()}", f"{platform.system()} {platform.release()}",
             f"machine {platform.machine()}"]
    if platform.system() == "Darwin":
        parts.append(f"macOS {platform.mac_ver()[0]}")
    for package in ("bleak", "rivian-python-client", "cryptography", "dbus-fast", "pyobjc-framework-CoreBluetooth"):
        try:
            parts.append(f"{package} {version(package)}")
        except PackageNotFoundError:
            pass
    return ", ".join(parts)


log = Log()


def give_back_to_sudo_user(*paths):
    """Running as root (sudo, or a container)? Keep files owned by whoever owns this folder."""
    if os.geteuid() != 0:
        return
    owner = ROOT.stat()
    uid = int(os.environ.get("SUDO_UID") or owner.st_uid)
    gid = int(os.environ.get("SUDO_GID") or owner.st_gid)
    for path in paths:
        os.chown(path, uid, gid)


def die(message):
    log.debug(f"exit: {message}")
    print(f"error: {log.redact(message, screen=True)}", file=sys.stderr)
    sys.exit(1)


def save_json(path, data):
    """Write a secrets file readable only by the current user."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def load_json(path):
    with open(path) as handle:
        return json.load(handle)


KEY_SECRET_FIELDS = {
    "private_key": "private_key", "public_key": "public_key", "phone_id": "phone_id",
    "identity_id": "identity_id", "user_id": "user_id", "vehicle_id": "vehicle_id",
    "vas_vehicle_id": "vas_vehicle_id", "vehicle_public_key": "vehicle_public_key",
}


def key_path(name):
    return KEYS_DIR / f"{name}.json"


def key_names():
    return sorted(p.stem for p in KEYS_DIR.glob("*.json") if p != SESSION_FILE)


def load_key(name=None):
    """Load keys/<name>.json; with no name, use the only key there is."""
    if name is None:
        names = key_names()
        if len(names) != 1:
            die("no keys yet — run `rivian_key.py enroll NAME` first" if not names else
                "several keys — pick one with --key: " + ", ".join(repr(n) for n in names))
        name = names[0]
    path = key_path(name)
    if not path.exists():
        die(f"no key named {name!r} (have: {', '.join(key_names()) or 'none'})")
    key = load_json(path)
    for field, label in KEY_SECRET_FIELDS.items():
        log.secret(key.get(field), label)
    log.secret(key.get("vehicle_name"), "vehicle_name", whole_word=True)
    log.secret(key.get("name"), "key_name", whole_word=True)
    log.secret(key.get("device_name"), "key_name", whole_word=True)
    return key


def load_session():
    if not SESSION_FILE.exists():
        die("not logged in — run `rivian_key.py login` first")
    session = load_json(SESSION_FILE)
    log.secret(session.get("user_session_token"), "session_token")
    return session


def derive_secret(private_key_b64, vehicle_public_key_hex):
    """HKDF-SHA256(ECDH-P256(phone_private, vehicle_public)) — the BLE + command HMAC key.

    Same derivation as rivian-python-client's utils.get_secret_key().
    """
    private_key = serialization.load_pem_private_key(b64decode(private_key_b64), password=None)
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(vehicle_public_key_hex))
    shared = private_key.exchange(ec.ECDH(), public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"").derive(shared)
