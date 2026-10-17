"""Linux transport (BACKUP PATH — read LINUX.md first). Raw ATT over L2CAP + kernel SMP.

Why this is more involved than macOS:
  * BlueZ does not expose this truck's GATT over D-Bus, so we speak ATT on a raw L2CAP socket.
  * The truck only accepts SMP pairing whose request (a) offers our IRK and (b) does not
    demand MITM. A stock kernel/BlueZ setup does neither, so we:
      1. enable adapter privacy (MGMT SET_PRIVACY) — the kernel only distributes an IRK then;
      2. register a NoInputNoOutput BlueZ agent as the default agent — bluetoothd then sets the
         adapter's IO capability to NoInputNoOutput (so the kernel doesn't ask for MITM) and the
         agent accepts the Just Works confirmation.
  * Needs root (raw L2CAP + MGMT). Leaves adapter privacy on; see --restore-adapter.

Verified on Debian 13 / kernel 6.12 / an Intel USB adapter, from a clean adapter. Other stacks may differ.
"""
import asyncio
import ctypes
import errno
import os
import select
import socket
import struct
import threading
import time
from collections import deque
from uuid import UUID

import protocol
from common import log

libc = ctypes.CDLL(None, use_errno=True)  # whatever C library Python uses (glibc or musl)

AF_BLUETOOTH, SOCK_SEQPACKET, SOCK_RAW = 31, 5, 3
BTPROTO_L2CAP, BTPROTO_HCI = 0, 1
ATT_CID, ADDR_LE_PUBLIC, ADDR_LE_RANDOM = 4, 1, 2
SOL_BLUETOOTH, BT_SECURITY = 274, 4
HCI = 0  # adapter index (hci0)


class AttError(Exception):
    def __init__(self, opcode, handle, code):
        self.opcode, self.handle, self.code = opcode, handle, code
        super().__init__(f"ATT error 0x{code:02x} (request 0x{opcode:02x}, handle 0x{handle:04x})")


class _SockaddrL2(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("psm", ctypes.c_ushort),
                ("bdaddr", ctypes.c_ubyte * 6), ("cid", ctypes.c_ushort), ("addr_type", ctypes.c_ubyte)]


def _sockaddr(address, addr_type):
    sa = _SockaddrL2()
    sa.family, sa.cid, sa.addr_type = AF_BLUETOOTH, ATT_CID, addr_type
    sa.bdaddr = (ctypes.c_ubyte * 6)(*[int(x, 16) for x in address.split(":")[::-1]])
    return sa


def connect_att(address):
    fd = libc.socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "L2CAP socket (are you root?)")
    sock = socket.socket(fileno=fd)
    try:
        if libc.bind(fd, ctypes.byref(_sockaddr("00:00:00:00:00:00", ADDR_LE_PUBLIC)),
                     ctypes.sizeof(_SockaddrL2)) < 0:
            raise OSError(ctypes.get_errno(), "L2CAP bind")
        sock.setblocking(False)
        if libc.connect(fd, ctypes.byref(_sockaddr(address, ADDR_LE_RANDOM)),
                        ctypes.sizeof(_SockaddrL2)) < 0:
            code = ctypes.get_errno()
            if code != errno.EINPROGRESS:
                raise OSError(code, "L2CAP connect")
            _, ready, _ = select.select([], [sock], [], 10)
            if not ready:
                raise TimeoutError("L2CAP connect timed out")
            code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if code:
                raise OSError(code, "L2CAP connect")
        sock.settimeout(5)
        return sock
    except BaseException:
        sock.close()
        raise


class AttClient:
    """Minimal ATT client: one outstanding request; notifications queued separately."""

    def __init__(self, sock):
        self.sock = sock
        self.notifications = deque()
        self.mtu = 23

    def send(self, pdu):
        log.debug(f"ATT TX {pdu.hex()}")
        self.sock.send(pdu)

    def receive(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ATT receive deadline exceeded")
        self.sock.settimeout(remaining)
        pdu = self.sock.recv(517)
        if not pdu:
            raise ConnectionError("ATT connection closed")
        log.debug(f"ATT RX {pdu.hex()}")
        return pdu

    def _queue_notification(self, pdu):
        if pdu[0] not in (0x1B, 0x1D):
            return False
        if pdu[0] == 0x1D:
            self.send(b"\x1e")  # confirm indication
        self.notifications.append((struct.unpack_from("<H", pdu, 1)[0], pdu[3:]))
        return True

    def request(self, pdu, expected, timeout=5):
        self.send(pdu)
        deadline = time.monotonic() + timeout
        while True:
            response = self.receive(deadline)
            if self._queue_notification(response):
                continue
            if response[0] == 0x01 and len(response) == 5:
                raise AttError(response[1], struct.unpack_from("<H", response, 2)[0], response[4])
            if response[0] != expected:
                raise ValueError(f"unexpected ATT opcode 0x{response[0]:02x}")
            return response

    def exchange_mtu(self):
        response = self.request(struct.pack("<BH", 0x02, 517), 0x03)
        self.mtu = max(23, min(517, struct.unpack_from("<H", response, 1)[0]))

    def write(self, handle, payload):
        if len(payload) + 3 > self.mtu:
            raise ValueError("payload exceeds negotiated ATT MTU")
        self.request(struct.pack("<BH", 0x12, handle) + payload, 0x13)

    def wait_notify(self, handle, timeout):
        deadline = time.monotonic() + timeout
        while True:
            for index, (received, payload) in enumerate(self.notifications):
                if received == handle:
                    del self.notifications[index]
                    return payload
            try:
                response = self.receive(deadline)
            except (TimeoutError, socket.timeout):
                return None
            self._queue_notification(response)

    def security_state(self):
        level, key_size = self.sock.getsockopt(SOL_BLUETOOTH, BT_SECURITY, 2)
        return level, key_size

    def request_security(self, level):
        """Ask the kernel to run SMP on this link (BT_SECURITY level 2 = unauthenticated encryption)."""
        self.sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, bytes([level, 0]))
        _, ready, _ = select.select([], [self.sock], [], 20)
        if not ready:
            raise TimeoutError("link security upgrade timed out")
        error = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error:
            raise OSError(error, "link security upgrade")
        current, key_size = self.security_state()
        if current < level or not key_size:
            raise ValueError("link was not encrypted after SMP")
        log(f"link encrypted: level {current}, key size {key_size}")

    def discover(self):
        """Characteristic UUID -> (value_handle, cccd_handle). Handles can differ between trucks."""
        decls = []
        start = 1
        while start <= 0xFFFF:
            try:
                resp = self.request(struct.pack("<BHH", 0x08, start, 0xFFFF) + b"\x03\x28", 0x09)
            except AttError as error:
                if error.code == 0x0A:  # attribute not found = done
                    break
                raise
            length = resp[1]
            for i in range(2, len(resp), length):
                entry = resp[i:i + length]
                decl, value_handle = struct.unpack_from("<H", entry, 0)[0], struct.unpack_from("<H", entry, 3)[0]
                raw = entry[5:]
                uuid = (str(UUID(bytes=raw[::-1])) if len(raw) == 16
                        else f"0000{struct.unpack('<H', raw)[0]:04x}-0000-1000-8000-00805f9b34fb")
                decls.append((decl, value_handle, uuid))
                start = decl + 1
        result = {}
        for index, (_, value_handle, uuid) in enumerate(decls):
            end = decls[index + 1][0] - 1 if index + 1 < len(decls) else 0xFFFF
            cccd = None
            if value_handle < end:
                try:
                    resp = self.request(struct.pack("<BHH", 0x04, value_handle + 1, end), 0x05)
                    if resp[1] == 1:  # 16-bit UUIDs
                        for j in range(2, len(resp), 4):
                            handle, short = struct.unpack_from("<HH", resp, j)
                            if short == 0x2902:
                                cccd = handle
                except AttError:
                    pass
            result[uuid] = (value_handle, cccd)
        return result


# ── adapter setup (MGMT socket) ───────────────────────────────────────
class _Mgmt:
    class _Sockaddr(ctypes.Structure):
        _fields_ = [("family", ctypes.c_ushort), ("dev", ctypes.c_ushort), ("channel", ctypes.c_ushort)]

    def __init__(self, index):
        self.index = index
        self.fd = libc.socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "MGMT socket (are you root?)")
        sa = self._Sockaddr(AF_BLUETOOTH, 0xFFFF, 3)  # HCI_DEV_NONE, HCI_CHANNEL_CONTROL
        if libc.bind(self.fd, ctypes.byref(sa), ctypes.sizeof(sa)) < 0:
            raise OSError(ctypes.get_errno(), "MGMT bind")
        timeout = struct.pack("ll", 3, 0)
        libc.setsockopt(self.fd, 1, 20, timeout, len(timeout))  # SO_RCVTIMEO

    def cmd(self, opcode, params=b""):
        header = struct.pack("<HHH", opcode, self.index, len(params))
        libc.send(self.fd, header + params, len(header) + len(params), 0)
        buf = ctypes.create_string_buffer(4096)
        for _ in range(20):
            n = libc.recv(self.fd, buf, 4096, 0)
            if n <= 0:
                return -1, b""
            data = buf.raw[:n]
            if len(data) >= 9 and struct.unpack_from("<H", data, 0)[0] in (1, 2):  # Complete / Status
                code, status = struct.unpack_from("<HB", data, 6)
                if code == opcode:
                    if status:
                        log.debug(f"MGMT 0x{opcode:04x} failed with status 0x{status:02x}")
                    return status, data[9:]
        return -1, b""

    def settings(self):
        status, info = self.cmd(0x0004)  # READ_INFO
        return struct.unpack_from("<I", info, 13)[0] if status == 0 and len(info) >= 17 else 0

    def set_privacy(self, enabled):
        powered = self.settings() & 1
        if powered:
            self.cmd(0x0005, b"\x00")  # SET_POWERED off (privacy needs the adapter down)
            time.sleep(0.3)
        status, _ = self.cmd(0x002F, (b"\x01" + os.urandom(16)) if enabled else b"\x00" + bytes(16))
        if powered:
            self.cmd(0x0005, b"\x01")
            time.sleep(0.5)
        return status

    def close(self):
        libc.close(self.fd)


SETTING_NAMES = ["powered", "connectable", "fast-conn", "discoverable", "bondable", "link-sec",
                 "ssp", "br/edr", "hs", "le", "advertising", "secure-conn", "debug-keys", "privacy"]


def prepare_adapter(index):
    """Adapter prerequisites for the truck's pairing: LE Secure Connections and our IRK.

    No MITM: our NoInputNoOutput agent (start_agent) becomes bluetoothd's default agent, which
    sets the adapter's IO capability so the kernel asks for Just Works (verified with btmon).
    """
    mgmt = _Mgmt(index)
    try:
        status, info = mgmt.cmd(0x0004)  # READ_INFO
        if status != 0 or len(info) < 17:
            raise OSError(f"no Bluetooth adapter hci{index} (is it plugged in / not blocked by rfkill?)")
        supported, current = struct.unpack_from("<II", info, 9)
        if not supported & (1 << 9) or not supported & (1 << 11):
            raise OSError("this Bluetooth adapter can't do LE Secure Connections (needs Bluetooth 4.2 or newer)")
        if not current & (1 << 13):
            log("enabling adapter privacy (so pairing shares our identity key) — adapter restarts once")
            if mgmt.set_privacy(True) != 0:
                raise OSError("could not enable adapter privacy (MGMT SET_PRIVACY failed)")
        mgmt.cmd(0x0009, b"\x01")  # SET_BONDABLE
        mgmt.cmd(0x002D, b"\x01")  # SET_SECURE_CONN
        current = mgmt.settings()
        log.debug("adapter settings: " + " ".join(n for i, n in enumerate(SETTING_NAMES) if current & (1 << i)))
    finally:
        mgmt.close()


def restore_adapter_fully(index):
    """Turn adapter privacy back off (the only lasting change we make)."""
    mgmt = _Mgmt(index)
    try:
        log(f"adapter privacy off: {'ok' if mgmt.set_privacy(False) == 0 else 'failed'}")
    finally:
        mgmt.close()


# ── BlueZ agent (dbus-fast, already a bleak dependency on Linux) ──────
def start_agent():
    """Register a NoInputNoOutput agent so bluetoothd accepts the Just Works confirmation."""
    from dbus_fast import BusType
    from dbus_fast.aio import MessageBus
    from dbus_fast.service import ServiceInterface, method

    class Agent(ServiceInterface):
        def __init__(self):
            super().__init__("org.bluez.Agent1")

        @method()
        def Release(self):
            pass

        @method()
        def RequestConfirmation(self, device: "o", passkey: "u"):  # noqa: F821
            log("agent: confirming Just Works pairing")

        @method()
        def RequestAuthorization(self, device: "o"):  # noqa: F821
            log("agent: authorizing pairing")

        @method()
        def AuthorizeService(self, device: "o", uuid: "s"):  # noqa: F821
            pass

        @method()
        def RequestPinCode(self, device: "o") -> "s":  # noqa: F821
            return ""

        @method()
        def RequestPasskey(self, device: "o") -> "u":  # noqa: F821
            return 0

        @method()
        def DisplayPasskey(self, device: "o", passkey: "u", entered: "q"):  # noqa: F821
            pass

        @method()
        def DisplayPinCode(self, device: "o", pincode: "s"):  # noqa: F821
            pass

        @method()
        def Cancel(self):
            pass

    ready = threading.Event()

    async def run():
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        path = "/rivian_gen2_key/agent"
        bus.export(path, Agent())
        introspection = await bus.introspect("org.bluez", "/org/bluez")
        manager = bus.get_proxy_object("org.bluez", "/org/bluez", introspection) \
            .get_interface("org.bluez.AgentManager1")
        await manager.call_register_agent(path, "NoInputNoOutput")
        await manager.call_request_default_agent(path)
        log("agent: NoInputNoOutput registered as default")
        ready.set()
        await asyncio.Event().wait()

    def thread():
        try:
            asyncio.run(run())
        except Exception as error:  # noqa: BLE001 — report and let pairing fail visibly
            log(f"agent: failed to register: {error}")
            ready.set()

    threading.Thread(target=thread, daemon=True).start()
    ready.wait(5)


def find_truck(vas_vehicle_id, timeout):
    from bleak import BleakScanner

    async def scan():
        log(f"scanning up to {timeout:.0f}s for the truck (service <vas_vehicle_id>)")
        device = await BleakScanner.find_device_by_filter(
            lambda d, adv: vas_vehicle_id in (adv.service_uuids or []), timeout=timeout)
        return device and device.address
    return asyncio.run(scan())


def pair(secret, phone_id, vehicle_id, vas_vehicle_id, args):
    if os.geteuid() != 0:
        log("Linux pairing needs root (raw Bluetooth sockets) — re-run with sudo")
        return False
    try:
        prepare_adapter(HCI)
        start_agent()
        address = find_truck(vas_vehicle_id, args.scan)
        if not address:
            log("truck not found — is it in Set Up for this key?")
            return False
        log("connecting (raw ATT)")
        with connect_att(address) as sock:
            att = AttClient(sock)
            att.exchange_mtu()
            log.debug(f"ATT MTU {att.mtu}")
            handles = att.discover()
            for uuid, (value, cccd) in handles.items():
                log.debug(f"char {uuid} value=0x{value:04x} cccd={cccd and f'0x{cccd:04x}'}")
            try:
                q, _ = handles[protocol.Q]
                r, r_cccd = handles[protocol.R]
                _, t_cccd = handles[protocol.T]
            except KeyError:
                log("phone-key characteristics missing — the truck only exposes them in Set Up")
                return False

            att.write(r_cccd, b"\x01\x00")
            log("R subscribed")
            phone_nonce = os.urandom(16)
            att.write(q, protocol.build_auth1(secret, phone_id, phone_nonce))
            log("auth#1 written")
            response = att.wait_notify(r, 8)
            if response is None:
                log("no reply to auth#1 within 8s")
                return False
            vehicle_nonce, seq = protocol.verify_auth1_response(response, secret, vehicle_id, phone_nonce)
            log(f"auth#1 reply — vehicle signature VERIFIED (seq {seq})")
            att.write(q, protocol.build_auth2(secret, phone_id, phone_nonce, vehicle_nonce, model=args.model))
            log("auth#2 written")
            try:
                att.write(t_cccd, b"\x01\x00")
                log("T subscribe acknowledged without pairing (already bonded?)")
            except AttError as error:
                if error.code not in (0x05, 0x0F):
                    raise
                log(f"T subscribe -> {error} (expected) — starting SMP")
                att.request_security(2)
                att.write(t_cccd, b"\x01\x00")
            log("*** PAIRED — T subscribe succeeded on the encrypted link ***")
            try:
                att.wait_notify(0xFFFF, args.hold)
            except OSError:
                log.debug("vehicle disconnected after pairing (normal)")
            return True
    except (OSError, AttError, ValueError, TimeoutError) as error:
        log.exception(f"FAILED: {type(error).__name__}: {error}")
        return False
