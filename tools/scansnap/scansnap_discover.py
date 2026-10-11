#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
"""Experimental iX1300 discovery, derived from ScanSnap Home's DeviceFinder.

The optional hello probe opens the advertised TCP ports and reads greetings.
No reservation, pairing or scan commands are sent.
See README.md in this directory for scope and usage.
"""

import argparse
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time


DISCOVERY_PORT = 52217
REPLY_PORT = 55274
KEYS = {b"VENS", b"SSEN", b"SNSN", b"SAV2", b"ssNR"}


def route_identity(target):
    """Find the source IPv4 address and interface Linux would use for target."""
    target = str(ipaddress.IPv4Address(target))
    try:
        output = subprocess.check_output(
            ["ip", "-j", "-4", "route", "get", target], text=True,
            stderr=subprocess.PIPE,
        )
        routes = json.loads(output)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not determine route to {target}: {exc}") from exc
    if not routes or not isinstance(routes[0], dict):
        raise ValueError(f"no route to {target}")
    route = routes[0]
    interface = route.get("dev")
    local_ip = route.get("prefsrc") or route.get("src")
    if not interface or not local_ip:
        raise ValueError(f"route to {target} lacks source address or interface")
    ipaddress.IPv4Address(local_ip)
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]+", interface):
        raise ValueError("invalid interface name in route")
    return local_ip, interface


def mac_bytes(value):
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        raise ValueError("MAC must contain six colon-separated hex bytes")
    return bytes.fromhex(value.replace(":", ""))


def discovery_request(local_ip, mac, reply_port=REPLY_PORT):
    """32-byte VENS request, interface version 0x0010 (iX1300)."""
    if len(mac) != 6:
        raise ValueError("MAC must contain six bytes")
    if not 1 <= reply_port <= 65535:
        raise ValueError("reply port must be in 1..65535")
    ip = ipaddress.IPv4Address(local_ip).packed
    if ip == b"\x00" * 4:
        raise ValueError("local IP must be a concrete interface address")
    return struct.pack(
        ">4sI4s6s2xIHHI", b"VENS", 0, ip, mac, reply_port, 0x10, 0, 0
    )


def discovery_reply(data):
    """Decode one UDP payload, checking lengths before reading optional fields.

    The app allocates 163 bytes for receives. Only a prefix is understood here;
    trailing bytes are preserved instead of assigning unverified meanings.
    """
    data = bytes(data)
    if len(data) < 40:
        raise ValueError("truncated discovery header (need 40 bytes)")
    key, notify, status, version, host_type, password = struct.unpack_from(
        ">4sHHHHI", data
    )
    if key not in KEYS:
        raise ValueError("unknown discovery magic")
    if notify not in (0, 1):
        raise ValueError("not a discovery reply (possibly keepalive)")
    if status != 0:
        raise ValueError(f"discovery status is {status}")
    scanner = host_type in (0, 48)
    # Host name is 64 bytes; scanner product adds 16; 12 reserved follow.
    base_length = 132 if scanner else 116
    if len(data) < base_length:
        raise ValueError(f"truncated discovery identity (need {base_length} bytes)")

    def text_at(start, size):
        return data[start:start + size].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ).strip()

    port1, port2 = struct.unpack_from(">II", data, 20)
    legacy_status = struct.unpack_from(">I", data, 36)[0]
    action_mode = data[36] if version >= 6 else legacy_status >> 24
    occupied = struct.unpack_from(">H", data, 38)[0] if version >= 6 else None
    product = text_at(104, 16) if scanner else "PC"
    result = {
        "magic": key.decode("ascii"),
        "notify_code": notify,
        "interface_version": version,
        "host_type": host_type,
        "password_required": bool(password),
        "ip": str(ipaddress.IPv4Address(data[16:20])),
        "scanner_port": port1,
        "application_port": port2,
        "mac": ":".join(f"{b:02x}" for b in data[28:34]),
        "host_name": text_at(40, 64),
        "product": product,
        "action_mode": action_mode,
        "scanner_status": data[37] if version >= 6 else None,
        "occupied_status": occupied,
        "legacy_status": legacy_status if version < 6 else None,
        "red_mode": bool(action_mode & 8),
        "connection_encrypted_flag": bool(action_mode & 4),
    }
    cursor = base_length
    has_serial = (
        0x100 <= version <= 0x1ff or 0x10 <= version <= 0x1f
        or host_type == 0 or "ix100" in product.lower()
    )
    if has_serial:
        if len(data) < cursor + 12:
            raise ValueError("truncated serial-number block")
        result["serial"] = text_at(cursor, 10)
        cursor += 12
    if cursor == 144 and len(data) > cursor:
        if len(data) < 146:
            raise ValueError("truncated device-occupancy field")
        result["device_occupancy_state"] = struct.unpack_from(">H", data, cursor)[0]
        cursor += 2
    if cursor == 146 and len(data) > cursor:
        result["profile_setting_state"] = data[cursor]
        cursor += 1
    if cursor == 147 and len(data) > cursor:
        result["red_config_flag"] = data[cursor]
        cursor += 1
    result["unparsed_tail_hex"] = data[cursor:].hex()
    return result


def parse_greeting(data, expected_magic):
    """Decode the 16-byte TCP greeting read before any client command."""
    if len(data) != 16:
        raise ValueError(f"TCP greeting has {len(data)} bytes, expected 16")
    length, magic, status, trailer = struct.unpack(">I4sII", data)
    if length != 16:
        raise ValueError(f"TCP greeting declares {length} bytes, expected 16")
    if magic != expected_magic:
        raise ValueError(f"TCP greeting magic {magic!r} differs from discovery")
    return {"raw_hex": data.hex(), "magic": magic.decode("ascii"),
            "status": status, "trailer_hex": f"{trailer:08x}"}


def read_greeting(ip, port, local_ip, expected_magic, timeout):
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid advertised TCP port: {port}")
    with socket.create_connection((ip, port), timeout=timeout,
                                  source_address=(local_ip, 0)) as sock:
        sock.settimeout(timeout)
        data = bytearray()
        while len(data) < 16:
            part = sock.recv(16 - len(data))
            if not part:
                raise ValueError(f"TCP connection closed after {len(data)} greeting bytes")
            data.extend(part)
    return parse_greeting(data, expected_magic)


def discover(args, packet):
    target = str(ipaddress.IPv4Address(args.target))
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
        raise ValueError("timeout must be greater than 0 and at most 60 seconds")
    if not 1 <= args.retries <= 10:
        raise ValueError("retries must be in 1..10")
    records = []
    seen = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Binding selects the requested source address and detects port conflicts.
        sock.bind((args.local_ip, args.reply_port))
        print(f"Sending {args.retries} discovery request(s) from "
              f"{args.local_ip}:{args.reply_port} to {target}:{DISCOVERY_PORT}",
              file=sys.stderr)
        for attempt in range(args.retries):
            sock.sendto(packet, (target, DISCOVERY_PORT))
            if attempt + 1 < args.retries:
                time.sleep(0.5)
        deadline = time.monotonic() + args.timeout
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                break
            if peer[0] == args.local_ip and data == packet:
                continue
            try:
                decoded = discovery_reply(data)
            except ValueError as exc:
                print(f"Ignored UDP payload from {peer[0]}: {exc}", file=sys.stderr)
                continue
            identity = (peer[0], data)
            if identity not in seen:
                seen.add(identity)
                records.append({"peer": list(peer), "payload_hex": data.hex(),
                                "decoded": decoded})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("request", "discover", "hello"):
        sub = commands.add_parser(command)
        sub.add_argument("--local-ip", required=command == "request",
                         help="Linux host's LAN IPv4 address (auto-detected for discover/hello)")
        identity = sub.add_mutually_exclusive_group(required=command == "request")
        identity.add_argument("--interface", help="read MAC from /sys/class/net/<name>/address")
        identity.add_argument("--mac", help="Linux host interface MAC address")
        sub.add_argument("--reply-port", type=int, default=REPLY_PORT)
        if command in ("discover", "hello"):
            sub.add_argument("--target", default="255.255.255.255",
                             help="scanner IPv4 address or subnet broadcast")
            sub.add_argument("--timeout", type=float, default=5)
            sub.add_argument("--retries", type=int, default=3,
                             help="discovery requests spaced 0.5 seconds apart (default: 3)")
    decode = commands.add_parser("decode", help="decode a saved binary UDP payload offline")
    decode.add_argument("payload", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "decode":
            print(json.dumps(discovery_reply(args.payload.read_bytes()), indent=2))
            return 0
        if args.command in ("discover", "hello") and (not args.local_ip or not (args.interface or args.mac)):
            detected_ip, detected_interface = route_identity(args.target)
            args.local_ip = args.local_ip or detected_ip
            if not (args.interface or args.mac):
                args.interface = detected_interface
        if args.interface:
            if not re.fullmatch(r"[a-zA-Z0-9_.:-]+", args.interface):
                raise ValueError("invalid interface name")
            mac = mac_bytes((Path("/sys/class/net") / args.interface / "address").read_text().strip())
        else:
            mac = mac_bytes(args.mac)
        packet = discovery_request(args.local_ip, mac, args.reply_port)
        if args.command == "request":
            print(packet.hex())
            return 0
        records = discover(args, packet)
        if args.command == "hello":
            if not records:
                print("No discovery reply received; TCP ports are unknown.", file=sys.stderr)
                return 1
            record = next((r for r in records if r["peer"][0] == args.target), records[0])
            device = record["decoded"]
            if device["red_mode"]:
                raise ValueError("RED/TLS mode is advertised; plain TCP hello probe is disabled")
            result = {"discovery": device, "greetings": {}}
            for label, port_name in (("application", "application_port"),
                                     ("scanner", "scanner_port")):
                try:
                    result["greetings"][label] = read_greeting(
                        record["peer"][0], device[port_name], args.local_ip,
                        device["magic"].encode("ascii"), 3.0)
                except (OSError, ValueError) as exc:
                    result["greetings"][label] = {"error": str(exc)}
            print(json.dumps(result, indent=2))
            return 0 if all("error" not in value for value in result["greetings"].values()) else 1
        print(json.dumps(records, indent=2))
        if not records:
            print("No discovery replies received; scanner support is not determined.", file=sys.stderr)
        return 0 if records else 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
