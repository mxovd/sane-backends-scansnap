#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
"""Experimental iX1300 reserve / INQUIRY / release probe.

No scan, pairing, configuration, firmware, or cloud commands are sent. The
scanner is released in a finally block after any attempted reservation.
"""

import argparse
from contextlib import closing
from datetime import datetime
import ipaddress
import json
from pathlib import Path
import socket
import struct
import sys
from types import SimpleNamespace

from scansnap_discover import (
    DISCOVERY_PORT, REPLY_PORT, discover, discovery_request, mac_bytes,
    parse_greeting, route_identity,
)


TRIGGER_PORT = 55275
TCP_TIMEOUT = 8


class ProtocolError(ValueError):
    pass


def reserve_request(magic, identity, local_ip, trigger_port, now=None):
    if len(magic) != 4 or len(identity) != 6:
        raise ValueError("invalid magic or client identity")
    if not 1 <= trigger_port <= 65535:
        raise ValueError("invalid trigger port")
    now = now or datetime.now().astimezone()
    packet = bytearray(128)
    struct.pack_into(">I4sII6s", packet, 0, 128, magic, 17, 0, identity)
    struct.pack_into(">HBBII4sI", packet, 32, 16, 30, 0, 1, 0,
                     ipaddress.IPv4Address(local_ip).packed, trigger_port)
    date = (now.year << 16) | (now.month << 8) | now.day
    clock = (now.hour << 24) | (now.minute << 16) | (now.second << 8)
    offset = now.utcoffset()
    seconds_west = -int(offset.total_seconds()) if offset is not None else 0
    struct.pack_into(">IIii", packet, 100, date, clock, 0, 0)
    struct.pack_into(">i", packet, 116, seconds_west)
    return bytes(packet)


def release_request(magic, identity, reason=1):
    if len(magic) != 4 or len(identity) != 6:
        raise ValueError("invalid magic or client identity")
    return struct.pack(">I4sII6s2xII", 32, magic, 18, 0, identity, reason, 0)


def inquiry_request(magic, identity, vpd=False):
    if len(magic) != 4 or len(identity) != 6:
        raise ValueError("invalid magic or client identity")
    packet = bytearray(64)
    struct.pack_into(">I4sII6s", packet, 0, 64, magic, 1, 0, identity)
    incoming = 144 if vpd else 96
    struct.pack_into(">IIII", packet, 32, 6, incoming, 0, 0)
    packet[48:54] = (b"\x12\x01\xf0\x00\x90\x00" if vpd
                     else b"\x12\x00\x00\x00\x60\x00")
    return bytes(packet)


def hardware_status_request(magic, identity):
    """Build the app's read-only GET HARDWARE STATUS command (CDB 0xc2)."""
    if len(magic) != 4 or len(identity) != 6:
        raise ValueError("invalid magic or client identity")
    packet = bytearray(64)
    struct.pack_into(">I4sII6s", packet, 0, 64, magic, 1, 0, identity)
    struct.pack_into(">IIII", packet, 32, 10, 32, 0, 0)
    packet[48] = 0xc2
    packet[56] = 32
    return bytes(packet)


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        block = sock.recv(length - len(data))
        if not block:
            raise ProtocolError(f"connection closed after {len(data)} of {length} bytes")
        data.extend(block)
    return bytes(data)


def connect_and_greet(ip, port, local_ip, magic):
    if not 1 <= port <= 65535:
        raise ProtocolError(f"invalid advertised TCP port {port}")
    sock = socket.create_connection((ip, port), timeout=TCP_TIMEOUT,
                                    source_address=(local_ip, 0))
    try:
        sock.settimeout(TCP_TIMEOUT)
        greeting = parse_greeting(read_exact(sock, 16), magic)
        if greeting["status"] != 0:
            raise ProtocolError(f"TCP greeting status {greeting['status']}")
        return sock
    except BaseException:
        sock.close()
        raise


def parse_app_ack(data, magic, expected_length):
    if len(data) != expected_length:
        raise ProtocolError("application reply has wrong size")
    length, actual_magic, status = struct.unpack_from(">I4si", data)
    if length != expected_length or actual_magic != magic:
        raise ProtocolError("application reply length or magic mismatch")
    result = {"raw_hex": data.hex(), "status": status}
    if expected_length == 20:
        result["interface_version"] = struct.unpack_from(">H", data, 12)[0]
    return result


def parse_inquiry_reply(header, payload, magic, decode_identity=True):
    if len(header) != 40:
        raise ProtocolError("scanner reply header has wrong size")
    length, actual_magic, status, scanner_status = struct.unpack_from(">I4sii", header)
    if length < 40 or length > 4096 or actual_magic != magic:
        raise ProtocolError("scanner reply length or magic mismatch")
    if len(payload) != length - 40:
        raise ProtocolError("scanner reply payload length mismatch")
    result = {"raw_header_hex": header.hex(), "status": status,
              "scanner_status": scanner_status, "payload_hex": payload.hex()}
    if decode_identity and len(payload) >= 36:
        for label, start, end in (("vendor", 8, 16), ("product", 16, 32),
                                  ("revision", 32, 36)):
            result[label] = payload[start:end].decode("ascii", errors="replace").strip()
    return result


def decode_vpd_f0(payload):
    """Decode established Fujitsu VPD fields used by sane-fujitsu."""
    if len(payload) < 0x7d:
        raise ProtocolError(f"VPD F0 payload has only {len(payload)} bytes")
    if payload[1] != 0xf0:
        raise ProtocolError(f"expected VPD page f0, received {payload[1]:02x}")

    def u16(offset):
        return struct.unpack_from(">H", payload, offset)[0]

    def u32(offset):
        return struct.unpack_from(">I", payload, offset)[0]

    standard_dpi = (60, 75, 100, 120, 150, 160, 180, 200,
                    240, 300, 320, 400, 480, 600, 800, 1200)
    standard_mask = (payload[0x12] << 8) | payload[0x13]
    # Fujitsu numbers these flags MSB-first within each byte.
    standard_resolutions = [dpi for bit, dpi in enumerate(standard_dpi)
                            if standard_mask & (1 << (15 - bit))]
    source = payload[0x20]
    commands_26 = payload[0x26]
    commands_27 = payload[0x27]
    commands_28 = payload[0x28]
    commands_29 = payload[0x29]
    return {
        "page_code": payload[1],
        "page_length": payload[4],
        "basic_resolution_dpi": {"x": u16(0x05), "y": u16(0x07)},
        "resolution_is_stepwise": {
            "x": bool(payload[0x09] & 0x01),
            "y": bool(payload[0x09] & 0x10),
        },
        "maximum_resolution_dpi": {"x": u16(0x0a), "y": u16(0x0c)},
        "minimum_resolution_dpi": {"x": u16(0x0e), "y": u16(0x10)},
        "standard_resolutions_dpi": standard_resolutions,
        "maximum_window_basic_units": {"x": u32(0x14), "y": u32(0x18)},
        "sources": {
            "adf": bool(source & 0x80),
            "flatbed": bool(source & 0x40),
            "transparency": bool(source & 0x20),
            "duplex": bool(source & 0x10),
            "operator_panel": bool(source & 0x02),
        },
        "adf": {
            "multi_feed_detection": bool(payload[0x21] & 0x20),
            "paper_protection": bool(payload[0x21] & 0x10),
        },
        "buffer_bytes": u32(0x22),
        "legacy_commands": {
            "mode_sense_10": bool(commands_26 & 0x02),
            "mode_select_10": bool(commands_26 & 0x01),
            "read_buffer": bool(commands_27 & 0x10),
            "write_buffer": bool(commands_27 & 0x08),
            "send": bool(commands_28 & 0x40),
            "read": bool(commands_28 & 0x20),
            "get_window": bool(commands_28 & 0x10),
            "set_window": bool(commands_28 & 0x08),
            "scan": bool(commands_28 & 0x01),
            "inquiry": bool(commands_29 & 0x04),
            "request_sense": bool(commands_29 & 0x02),
            "test_unit_ready": bool(commands_29 & 0x01),
        },
        "extended_vpd_length": payload[0x6f],
        "extended": {
            "start_job": bool(payload[0x73] & 0x20),
            "lifetime_log": bool(payload[0x73] & 0x10),
            "synchronous_next_feed": payload[0x76] & 0x07,
            "read_size": bool(payload[0x78] & 0x40),
            "start_end_mode_sense": bool(payload[0x78] & 0x20),
            "battery_save": bool(payload[0x79] & 0x40),
            "return_path": bool(payload[0x7c] & 0x80),
        },
    }


def decode_hardware_status(payload):
    """Decode the fields consumed by ScanSnap Home from the 32-byte C2 reply."""
    if len(payload) != 32:
        raise ProtocolError(f"hardware status payload has {len(payload)} bytes")
    error_code = payload[7]
    flags_15 = payload[15]
    wifi = payload[16]
    battery = payload[17]
    profile = payload[21]
    return {
        "top": bool(payload[2] & 0x80),
        "hopper_empty": bool(payload[3] & 0x80),
        "paper_in_adf": not bool(payload[3] & 0x80),
        "adf_cover_open": bool(payload[3] & 0x20),
        "exit_sensor": bool(payload[3] & 0x01),
        "card_loaded": bool(payload[3] & 0x01),
        "sleeping": bool(payload[4] & 0x80),
        "long_sheet_switch": bool(payload[4] & 0x20),
        "scan_button": bool(payload[4] & 0x01),
        "double_feed": bool(payload[6] & 0x01),
        "device_error_code": error_code,
        "multi_feed_overlap": error_code == 0x55,
        "maximum_read_length_error": error_code == 0x31,
        "page_count_error": error_code == 0x5d,
        "paper_length_error": error_code == 0x5e,
        "scan_cancel": bool(flags_15 & 0x08),
        "non_separation_feed": bool(flags_15 & 0x10),
        "continuous_feed": bool(flags_15 & 0x20),
        "scan_end": bool(flags_15 & 0x40),
        "wifi_switch": bool(wifi & 0x80),
        "wifi_in_use": bool(wifi & 0x40),
        "wifi_state_bits": wifi & 0xf8,
        "battery_present": bool(battery & 0x80),
        "battery_charging": bool(battery & 0x40),
        "battery_temporary_stop": bool(payload[18] & 0x20),
        "battery_level_raw": payload[19],
        "profile_display_node1": bool(profile & 0x10),
        "profile_display_mode0": bool(profile & 0x08),
        "multi_feed_detection_disabled": bool(profile & 0x02),
        "save_multi_feed_image": bool(profile & 0x01),
        "raw_hex": payload.hex(),
    }


def run_inquiry(target, port, local_ip, magic, identity, vpd=False):
    with closing(connect_and_greet(target, port, local_ip, magic)) as scanner:
        scanner.sendall(inquiry_request(magic, identity, vpd=vpd))
        header = read_exact(scanner, 40)
        length = struct.unpack_from(">I", header)[0]
        if not 40 <= length <= 4096:
            raise ProtocolError(f"invalid scanner reply length {length}")
        result = parse_inquiry_reply(header, read_exact(scanner, length - 40), magic,
                                     decode_identity=not vpd)
        expected = 144 if vpd else 96
        if len(bytes.fromhex(result["payload_hex"])) != expected:
            raise ProtocolError(
                f"INQUIRY payload has {len(bytes.fromhex(result['payload_hex']))} bytes, "
                f"expected {expected}")
        if vpd:
            result["decoded"] = decode_vpd_f0(bytes.fromhex(result["payload_hex"]))
        return result


def run_hardware_status(target, port, local_ip, magic, identity):
    with closing(connect_and_greet(target, port, local_ip, magic)) as scanner:
        scanner.sendall(hardware_status_request(magic, identity))
        header = read_exact(scanner, 40)
        length = struct.unpack_from(">I", header)[0]
        if length != 72:
            raise ProtocolError(f"hardware status reply has invalid length {length}")
        result = parse_inquiry_reply(
            header, read_exact(scanner, 32), magic, decode_identity=False)
        result["decoded"] = decode_hardware_status(
            bytes.fromhex(result["payload_hex"]))
        return result


def probe(args):
    target = str(ipaddress.IPv4Address(args.target))
    local_ip, interface = route_identity(target)
    identity = mac_bytes((Path("/sys/class/net") / interface / "address").read_text().strip())
    search = SimpleNamespace(target=target, local_ip=local_ip,
                             reply_port=REPLY_PORT, timeout=5, retries=3)
    records = discover(search, discovery_request(local_ip, identity))
    record = next((item for item in records if item["peer"][0] == target), None)
    if record is None:
        raise ProtocolError("no discovery reply from target")
    device = record["decoded"]
    if (device["ip"] != target or device["magic"] != "VENS"
            or device["interface_version"] != 16 or device["host_type"] != 48
            or device["product"].lower() != "scansnap ix1300"):
        raise ProtocolError("discovery reply is not the expected iX1300 protocol")
    if device["red_mode"] or device["password_required"]:
        raise ProtocolError("TLS or password mode needs separate implementation")
    magic = device["magic"].encode("ascii")
    output = {"scanner_ip": target, "application_port": device["application_port"],
              "scanner_port": device["scanner_port"]}
    release_needed = False
    # Keep the trigger port bound throughout the reservation, as the app does.
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as trigger:
        trigger.bind((local_ip, TRIGGER_PORT))
        try:
            with closing(connect_and_greet(target, device["application_port"],
                                           local_ip, magic)) as app:
                request = reserve_request(magic, identity, local_ip, TRIGGER_PORT)
                release_needed = True
                app.sendall(request)
                reserve = parse_app_ack(read_exact(app, 20), magic, 20)
                output["reserve"] = reserve
                if reserve["status"] != 0:
                    release_needed = False
                    raise ProtocolError(f"reservation rejected with status {reserve['status']}")
                if reserve["interface_version"] < 2:
                    raise ProtocolError("reservation reported an unsupported interface version")
            output["inquiry"] = run_inquiry(
                target, device["scanner_port"], local_ip, magic, identity)
            if output["inquiry"]["status"] != 0 or output["inquiry"]["scanner_status"] != 0:
                raise ProtocolError("standard INQUIRY returned an error status")
            output["vpd_f0"] = run_inquiry(
                target, device["scanner_port"], local_ip, magic, identity, vpd=True)
            if (output["vpd_f0"]["status"] != 0
                    or output["vpd_f0"]["scanner_status"] != 0):
                raise ProtocolError("VPD F0 INQUIRY returned an error status")
            output["hardware_status"] = run_hardware_status(
                target, device["scanner_port"], local_ip, magic, identity)
        except (OSError, ValueError) as exc:
            output["error"] = str(exc)
        finally:
            if release_needed:
                try:
                    with closing(connect_and_greet(target, device["application_port"],
                                                   local_ip, magic)) as app:
                        app.sendall(release_request(magic, identity))
                        output["release"] = parse_app_ack(read_exact(app, 16), magic, 16)
                except (OSError, ValueError) as exc:
                    output["release"] = {"error": str(exc)}
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="current scanner IPv4 address")
    args = parser.parse_args()
    try:
        result = probe(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if ("error" not in result
                 and result.get("reserve", {}).get("status") == 0
                 and result.get("inquiry", {}).get("status") == 0
                 and result.get("inquiry", {}).get("scanner_status") == 0
                 and result.get("vpd_f0", {}).get("status") == 0
                 and result.get("vpd_f0", {}).get("scanner_status") == 0
                 and result.get("hardware_status", {}).get("status") == 0
                 and result.get("hardware_status", {}).get("scanner_status") == 0
                 and result.get("release", {}).get("status") == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
