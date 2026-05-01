"""
L4D2 Server Blocker

Intercepts A2S_GETCHALLENGE packets to blacklisted servers and injects
fake S2C_CONNREJECT responses for instant connection rejection.

Requirements: pip install pydivert
Must run as Administrator (WinDivert kernel driver).
"""

import json
import pydivert
import struct
import socket
import sys
from fnmatch import fnmatch
from pathlib import Path
from datetime import datetime

if getattr(sys, 'frozen', False):
    _BASE_DIR = Path(sys.executable).parent
else:
    _BASE_DIR = Path(__file__).parent
BLOCKLIST_PATH = _BASE_DIR / "blocked_servers.json"


def load_blocklist() -> list[str]:
    try:
        entries = json.loads(BLOCKLIST_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"[ERROR] {BLOCKLIST_PATH} not found.")
        sys.exit(1)
    return entries

REJECT_REASON = b"Server blocked by user"

# ──── Source Engine protocol constants ────
CONNECTIONLESS_HEADER = b'\xff\xff\xff\xff'
A2S_GETCHALLENGE = 0x71  # 'q'
S2C_CHALLENGE    = 0x41  # 'A'
S2C_CONNREJECT   = 0x39  # '9'
A2A_PRINT        = 0x6C  # 'l'


def extract_challenge(payload: bytes) -> bytes | None:
    """Extract m_retryChallenge from A2S_GETCHALLENGE packet.

    L4D2 format: FF FF FF FF 71 "connect0xXXXXXXXX\\0"  (challenge in hex string)
    Old format:  FF FF FF FF 71 <challenge:4 LE> "0000000000\\0"
    """
    if payload[5:14] == b'connect0x':
        try:
            return struct.pack('<I', int(payload[14:22], 16))
        except (ValueError, IndexError):
            return None
    return payload[5:9]


def build_reject_payload(challenge: bytes) -> bytes:
    """FF FF FF FF 39 <challenge:4> <reason\\0>"""
    return (
        CONNECTIONLESS_HEADER
        + bytes([S2C_CONNREJECT])
        + challenge
        + REJECT_REASON + b'\x00'
    )


def build_bad_challenge_payload(challenge: bytes) -> bytes:
    """Fake S2C_CHALLENGE with invalid auth protocol to force disconnect.

    FF FF FF FF 41 <challenge:4> <server_challenge:4> <auth_proto:4=0 (invalid)>
    Client reads auth protocol, sees it's not PROTOCOL_STEAM(3), calls Disconnect().
    """
    return (
        CONNECTIONLESS_HEADER
        + bytes([S2C_CHALLENGE])
        + challenge                    # echo client's retryChallenge
        + b'\x01\x02\x03\x04'         # fake server challenge
        + struct.pack('<I', 0)         # auth protocol = 0 (invalid, not PROTOCOL_STEAM=3)
    )


def build_print_payload(msg: str) -> bytes:
    """A2A_PRINT — prints message on client console (diagnostic)."""
    return (
        CONNECTIONLESS_HEADER
        + bytes([A2A_PRINT])
        + msg.encode() + b'\x00'
    )


def build_ip_udp(src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int,
                 payload: bytes) -> bytes:
    """Raw IPv4+UDP packet. Checksums set to 0 (WinDivert recalculates)."""
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)

    ip_total = 20 + udp_len
    ip_hdr = struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, ip_total,
        0, 0x4000,
        64, 17, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return ip_hdr + udp_hdr + payload


def build_filter(patterns: list[str]) -> str:
    """Build WinDivert filter from patterns. IP-level pre-filter; port matching in Python."""
    seen = set()
    conditions = []
    for pat in patterns:
        ip = pat.rsplit(":", 1)[0]
        port_pat = pat.rsplit(":", 1)[1]

        if '*' in ip or '?' in ip:
            octets = ip.split('.')
            lo = '.'.join('0' if ('*' in o or '?' in o) else o for o in octets)
            hi = '.'.join('255' if ('*' in o or '?' in o) else o for o in octets)
            ip_cond = (f"(ip.DstAddr >= {lo} and ip.DstAddr <= {hi})"
                       if lo != hi else f"ip.DstAddr == {lo}")
        else:
            ip_cond = f"ip.DstAddr == {ip}"

        if '*' not in port_pat and '?' not in port_pat:
            cond = f"({ip_cond} and udp.DstPort == {port_pat})"
        else:
            cond = ip_cond

        if cond not in seen:
            seen.add(cond)
            conditions.append(cond)

    return f"outbound and udp and ({' or '.join(conditions)})"


def is_blocked(dst_ip: str, dst_port: int, patterns: list[str]) -> bool:
    addr = f"{dst_ip}:{dst_port}"
    return any(fnmatch(addr, pat) for pat in patterns)


def log(tag: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{tag:6s}] {msg}")


def main():
    patterns = load_blocklist()
    if not patterns:
        print("No entries in blocklist.")
        return

    filt = build_filter(patterns)

    print("=" * 58)
    print("  L4D2 Server Blocker")
    print("=" * 58)
    for pat in sorted(patterns):
        print(f"  BLOCK  {pat}")
    print("=" * 58)
    print()

    try:
        with pydivert.WinDivert(filt) as w:
            log("INFO", "Listening... press Ctrl+C to stop")
            for packet in w:
                if not is_blocked(packet.dst_addr, packet.dst_port, patterns):
                    w.send(packet)
                    continue

                payload = packet.payload
                dst = f"{packet.dst_addr}:{packet.dst_port}"

                if (len(payload) >= 9
                        and payload[:4] == CONNECTIONLESS_HEADER
                        and payload[4] == A2S_GETCHALLENGE):

                    challenge = extract_challenge(payload)
                    if challenge is None:
                        log("DROP", f"{dst}  malformed getchallenge")
                        continue

                    # Inject up to 3 packets for diagnosis:
                    payloads = {
                        "PRINT":  build_print_payload(
                            "[BLOCKER] Server blocked!\n"),
                        "REJECT": build_reject_payload(challenge),
                        "BADAUTH": build_bad_challenge_payload(challenge),
                    }
                    for tag, pl in payloads.items():
                        raw = build_ip_udp(
                            packet.dst_addr, packet.src_addr,
                            packet.dst_port, packet.src_port,
                            pl,
                        )
                        resp = pydivert.Packet(
                            raw,
                            interface=packet.interface,
                            direction=pydivert.Direction.INBOUND,
                        )
                        resp.recalculate_checksums()
                        w.send(resp)
                    log("INJECT", f"{dst}  challenge={challenge.hex()}"
                        f"  sent PRINT+REJECT+BADAUTH")
                else:
                    ptype = (f"0x{payload[4]:02x}"
                             if len(payload) > 4 else "empty")
                    log("DROP", f"{dst}  type={ptype}  len={len(payload)}")
                    # not re-injected → silently dropped

    except KeyboardInterrupt:
        print()
        log("INFO", "Stopped.")
    except OSError as e:
        log("ERROR", str(e))
        if "access" in str(e).lower():
            log("ERROR", "Run as Administrator.")
        sys.exit(1)


if __name__ == "__main__":
    main()
