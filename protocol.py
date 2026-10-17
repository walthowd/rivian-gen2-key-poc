"""Gen 2 phone-key authentication messages (pure functions, no I/O).

See PROTOCOL.md for the wire format. All messages are protobuf; field numbers below are the
only schema needed. Every message written to Q is an envelope whose field 2 is a signed block:

  envelope { 2: signed { 1: message_list, 2: seq, [3|4: excludes phone|vehicle nonce], 5: signature { 1: 1 (HMAC-SHA256), 2: mac } } }
  mac = HMAC-SHA256(secret, message_list || seq(u32 LE) || sender_id(16) || phone_nonce || vehicle_nonce?)
"""
import hashlib
import hmac
import struct

# GATT (phone-key service, present only while the truck is in Set Up / bonded)
PHONE_KEY_SERVICE = "72cddca3-ab00-4e94-bae5-868f93f8c6c0"  # gitleaks:allow (public GATT UUID)
Q = "0823da14-040b-4914-bf7c-450afa2850da"   # write: phone -> vehicle, no encryption needed
R = "29919a3c-a697-4a6f-bd3b-d14860cc9bce"   # notify: vehicle -> phone, no encryption needed
S = "9a69aeff-e3fe-4e79-bb7d-5ae12272fd14"   # write: phone -> vehicle, encrypted link only
T = "5eaa65c0-57ee-4cf4-a3d5-a4aae20cbb0b"   # notify: vehicle -> phone, encrypted link only
CCCD = "00002902-0000-1000-8000-00805f9b34fb"

DEFAULT_MODEL = b"rivian-gen2-key-poc"


# ── protobuf encoding ────────────────────────────────────────────────
def _varint(n):
    out = b""
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def f_len(field, payload):
    return _varint((field << 3) | 2) + _varint(len(payload)) + payload


def f_var(field, value):
    return _varint((field << 3) | 0) + _varint(value)


def parse_fields(data):
    """Small bounded protobuf decoder: {field: [values...]}."""
    fields = {}
    offset = 0

    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError("truncated protobuf varint")
            byte = data[offset]
            offset += 1
            if shift == 63 and byte > 1:
                raise ValueError("protobuf varint overflow")
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError("protobuf varint overflow")

    while offset < len(data):
        tag = varint()
        field, wire = tag >> 3, tag & 7
        if not 0 < field < (1 << 29):
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value = varint()
        elif wire in (1, 2, 5):
            length = varint() if wire == 2 else (8 if wire == 1 else 4)
            if offset + length > len(data):
                raise ValueError("truncated protobuf field")
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        fields.setdefault(field, []).append(value)
    return fields


def one(fields, field, default=None):
    values = fields.get(field, [])
    if len(values) > 1:
        raise ValueError(f"ambiguous repeated singular field {field}")
    return values[0] if values else default


def _mac(secret, message_list, seq, sender_id, *nonces):
    return hmac.new(secret, message_list + struct.pack("<I", seq) + sender_id + b"".join(nonces),
                    hashlib.sha256).digest()


def _signed(message_list, seq, mac, excludes_vehicle_nonce=False):
    signature = f_var(1, 1) + f_len(2, mac)
    body = f_len(1, message_list) + f_var(2, seq) + (f_var(4, 1) if excludes_vehicle_nonce else b"")
    return f_len(2, body + f_len(5, signature))


# ── messages ─────────────────────────────────────────────────────────
def build_auth1(secret, phone_id, phone_nonce, seq=1):
    """Auth #1: transaction 1, credentials {phone_id, phone_nonce}. Signed without a vehicle nonce."""
    credentials = f_len(1, phone_id) + f_len(2, phone_nonce)
    message = f_var(1, 1) + f_len(5, f_len(1, credentials))
    message_list = f_len(1, message)
    return _signed(message_list, seq, _mac(secret, message_list, seq, phone_id, phone_nonce),
                   excludes_vehicle_nonce=True)


def build_auth2(secret, phone_id, phone_nonce, vehicle_nonce, model=DEFAULT_MODEL, seq=2):
    """Auth #2: transaction 3 = empty credentials, transaction 5 = client info {model string}.

    Byte-identical in structure to a real phone's auth #2 (over-the-air capture); only the
    model string differs (a phone sends its lowercase device model).
    """
    message_empty_auth = f_var(1, 3) + f_len(5, f_len(1, b""))
    client_info = f_len(1, f_len(2, model)) if model else f_len(1, b"")
    message_client = f_var(1, 5) + f_len(9, client_info)
    message_list = f_len(1, message_empty_auth) + f_len(1, message_client)
    return _signed(message_list, seq,
                   _mac(secret, message_list, seq, phone_id, phone_nonce, vehicle_nonce))


def verify_auth1_response(response, secret, vehicle_id, phone_nonce):
    """Check the vehicle's reply on R and return (vehicle_nonce, seq).

    The vehicle signs with its own ID as sender; both nonces must be covered so a captured
    reply can't be replayed.
    """
    envelope = parse_fields(response)
    signed = parse_fields(one(envelope, 2, b""))
    message_list = one(signed, 1, b"")
    messages = parse_fields(message_list).get(1, [])
    if not messages:
        raise ValueError("missing signed auth message")
    auth = parse_fields(one(parse_fields(messages[0]), 5, b""))
    credentials = parse_fields(one(auth, 1, b""))
    received_id = one(credentials, 1, b"")
    vehicle_nonce = one(credentials, 2, b"")
    if received_id and received_id != vehicle_id:
        raise ValueError("vehicle ID mismatch (wrong truck, or wrong --vehicle?)")
    if len(vehicle_nonce) != 16:
        raise ValueError("vehicle nonce must be 16 bytes")
    seq = one(signed, 2, 0)
    if not isinstance(seq, int) or not 0 <= seq <= 0xFFFFFFFF:
        raise ValueError("invalid vehicle sequence")
    signature = parse_fields(one(signed, 5, b""))
    mac = one(signature, 2, b"")
    if one(signature, 1) != 1 or len(mac) != 32:
        raise ValueError("missing/unsupported HMAC-SHA256 signature")
    if one(signed, 3, 0) or one(signed, 4, 0):
        raise ValueError("vehicle signature omits a session nonce; refusing")
    expected = _mac(secret, message_list, seq, vehicle_id, phone_nonce, vehicle_nonce)
    if not hmac.compare_digest(mac, expected):
        raise ValueError("vehicle HMAC verification FAILED — key/vehicle mismatch")
    return vehicle_nonce, seq
