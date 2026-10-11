#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
"""Experimental single-page ScanSnap iX1300 Wi-Fi scan probe.

Scans one loaded page as a 300 dpi color JPEG. This is a protocol-development
tool, not a SANE backend. It bounds received data and always attempts D8/D6
cleanup followed by release of the application reservation.
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
import time
from types import SimpleNamespace

from scansnap_discover import (
    REPLY_PORT, discover, discovery_request, mac_bytes, route_identity,
)
from scansnap_session import (
    ProtocolError, TCP_TIMEOUT, TRIGGER_PORT, connect_and_greet,
    decode_hardware_status, parse_app_ack, read_exact, release_request,
    reserve_request,
)


READ_BLOCK = 256_000
MAX_BLOCKS = 512
MAX_IMAGE_BYTES = 128 * 1024 * 1024


def scanner_request(magic, identity, cdb, incoming=0, outgoing=b""):
    if len(magic) != 4 or len(identity) != 6 or not 1 <= len(cdb) <= 16:
        raise ValueError("invalid scanner request identity, magic, or CDB")
    if incoming < 0 or incoming > MAX_IMAGE_BYTES or len(outgoing) > 65536:
        raise ValueError("scanner request transfer is too large")
    packet = bytearray(64 + len(outgoing))
    struct.pack_into(">I4sII6s", packet, 0, len(packet), magic, 1, 0, identity)
    struct.pack_into(">IIII", packet, 32, len(cdb), incoming, len(outgoing), 0)
    packet[48:48 + len(cdb)] = cdb
    packet[64:] = outgoing
    return bytes(packet)


def exchange(sock, magic, identity, cdb, incoming=0, outgoing=b""):
    sock.sendall(scanner_request(magic, identity, cdb, incoming, outgoing))
    header = read_exact(sock, 40)
    length, actual_magic, status, scanner_status = struct.unpack_from(">I4sii", header)
    if actual_magic != magic or not 40 <= length <= 40 + MAX_IMAGE_BYTES:
        raise ProtocolError("invalid scanner command reply header")
    payload = read_exact(sock, length - 40)
    return {
        "status": status,
        "scanner_status": scanner_status,
        "payload": payload,
        "raw_header_hex": header.hex(),
    }


def require_ok(reply, operation, payload_length=None):
    if reply["status"] != 0 or reply["scanner_status"] != 0:
        raise ProtocolError(
            f"{operation} failed: protocol={reply['status']} "
            f"scanner={reply['scanner_status']}")
    if payload_length is not None and len(reply["payload"]) != payload_length:
        raise ProtocolError(
            f"{operation} returned {len(reply['payload'])} payload bytes; "
            f"expected {payload_length}")


def hardware_status(sock, magic, identity):
    cdb = bytearray(10)
    cdb[0] = 0xc2
    cdb[8] = 32
    reply = exchange(sock, magic, identity, cdb, incoming=32)
    require_ok(reply, "GET HARDWARE STATUS", 32)
    return decode_hardware_status(reply["payload"])


def scan_parameters(feed, duplex=False):
    """Reproduce ScanSnap Home's fixed-color, 300 dpi, auto-length block."""
    if feed not in ("adf", "card"):
        raise ValueError("feed must be adf or card")
    data = bytearray(80)
    data[0] = 1                         # iX1300 parameter format
    if feed == "adf":
        data[1] = 3 if duplex else 1       # U-turn duplex / simplex
    else:
        data[1] = 6 if duplex else 4       # return duplex / simplex
    data[2] = 1                         # overscan
    data[3] = 1                         # automatic length
    data[4] = 0x80                      # host-side multi-feed handling
    data[5] = 1                         # automatic size detection
    data[6] = 0xc1 if feed == "adf" else 0x80
    data[7] = 0x80                      # fixed color mode
    data[8] = 0x80                      # do not delete blank pages
    data[9] = 0xc8
    data[10] = 0x80
    data[11] = 0x80
    if feed == "card":
        data[28] = 0x20                 # return-path setup, protection off
    data[31] = 48                       # one 48-byte window descriptor

    offset = 32
    data[offset + 0] = 0                # front window
    data[offset + 1] = 16               # JPEG data format
    struct.pack_into(">HH", data, offset + 2, 300, 300)
    data[offset + 6] = 5                # color composition
    data[offset + 7] = 0x82             # JPEG compression
    data[offset + 8] = 11               # middle compression setting
    struct.pack_into(">II", data, offset + 10, 10368,
                     17232 if feed == "adf" else 17424)
    data[offset + 18] = 4               # standard gamma
    data[offset + 22] = 1               # highlight
    data[offset + 23] = 1               # unsharp mask
    data[offset + 24] = 1               # sRGB
    return bytes(data)


def request_sense(sock, magic, identity):
    cdb = b"\x03\x00\x00\x00\x12\x00"
    reply = exchange(sock, magic, identity, cdb, incoming=18)
    require_ok(reply, "REQUEST SENSE", 18)
    payload = reply["payload"]
    flags = payload[2]
    return {
        "eom": bool(flags & 0x40),
        "ili": bool(flags & 0x20),
        "sense_key": flags & 0x0f,
        "information": struct.unpack_from(">I", payload, 3)[0],
        "asc": payload[12],
        "ascq": payload[13],
        "raw_hex": payload.hex(),
    }


def append_image_payload(image, payload):
    """Append an Android-style READ payload after its two control bytes."""
    if len(payload) < 2:
        raise ProtocolError("READ returned a truncated image block")
    image.extend(payload[2:])
    return len(payload) - 2


def simple_command(sock, magic, identity, opcode, operation):
    reply = exchange(sock, magic, identity, bytes([opcode, 0, 0, 0, 0, 0]))
    require_ok(reply, operation, 0)
    return reply


def select_feed(status, requested):
    detected = None
    if status["paper_in_adf"] and not status["card_loaded"]:
        detected = "adf"
    elif status["card_loaded"] and not status["paper_in_adf"]:
        detected = "card"
    if detected is None:
        raise ProtocolError("load exactly one page in either the top ADF or return slot")
    if requested != "auto" and requested != detected:
        raise ProtocolError(f"requested {requested}, but sensors report {detected}")
    return detected


def read_image(sock, magic, identity, page_id, front):
    image = bytearray()
    final_sense = None
    wire_block_lengths = []
    for sequence in range(MAX_BLOCKS):
        cdb = bytearray(12)
        cdb[0] = 0x28
        cdb[2] = 0
        cdb[3] = 2
        cdb[5] = 0 if front else 0x80
        cdb[6:9] = READ_BLOCK.to_bytes(3, "big")
        cdb[10] = page_id
        cdb[11] = sequence & 0xff
        reply = exchange(sock, magic, identity, cdb, incoming=READ_BLOCK)
        if reply["status"] != 0:
            raise ProtocolError(f"READ protocol status {reply['status']}")
        wire_block_lengths.append(len(reply["payload"]))
        if reply["scanner_status"] == 0:
            append_image_payload(image, reply["payload"])
            if len(image) > MAX_IMAGE_BYTES:
                raise ProtocolError("image exceeded safety limit")
            continue
        if reply["scanner_status"] != 2:
            raise ProtocolError(f"READ scanner status {reply['scanner_status']}")
        if reply["payload"]:
            append_image_payload(image, reply["payload"])
        final_sense = request_sense(sock, magic, identity)
        if final_sense["ili"] and final_sense["information"] <= READ_BLOCK:
            expected = READ_BLOCK - final_sense["information"]
            if len(reply["payload"]) != expected:
                raise ProtocolError(
                    f"ILI reports {expected} final wire bytes, received "
                    f"{len(reply['payload'])}")
        if final_sense["eom"]:
            break
        if (final_sense["sense_key"], final_sense["asc"], final_sense["ascq"]) == (3, 0x80, 0x13):
            continue
        raise ProtocolError(f"READ check condition: {final_sense}")
    else:
        raise ProtocolError("scan exceeded block limit")
    return bytes(image), {
        "page_id": page_id,
        "side": "front" if front else "back",
        "blocks": sequence + 1,
        "bytes": len(image),
        "wire_block_lengths": wire_block_lengths,
        "sense": final_sense,
    }


def scan_page(sock, magic, identity, requested_source, duplex=False):
    status = hardware_status(sock, magic, identity)
    feed = select_feed(status, requested_source)
    simple_command(sock, magic, identity, 0xd8, "CANCEL READ")

    params = scan_parameters(feed, duplex=duplex)
    cdb = bytearray(6)
    cdb[0] = 0xd4
    cdb[4] = len(params)
    require_ok(exchange(sock, magic, identity, cdb, outgoing=params), "SET PARAMS", 0)

    cdb = bytearray(6)
    cdb[0] = 0xd5
    cdb[4] = cdb[5] = 8
    started = exchange(sock, magic, identity, cdb, incoming=8, outgoing=bytes(8))
    require_ok(started, "START JOB", 8)
    job_id = struct.unpack_from(">I", started["payload"])[0]

    for attempt in range(40):
        paper = exchange(sock, magic, identity, b"\xe0\0\0\0\0\0")
        if paper["status"] != 0:
            raise ProtocolError(f"START PAPER protocol status {paper['status']}")
        if paper["scanner_status"] == 0:
            break
        if paper["scanner_status"] != 8:
            sense = request_sense(sock, magic, identity)
            raise ProtocolError(f"START PAPER failed: {sense}")
        time.sleep(0.1)
    else:
        raise ProtocolError("START PAPER remained busy")

    images = {}
    pages = []
    images["front"], page = read_image(sock, magic, identity, 0, True)
    pages.append(page)
    if duplex:
        images["back"], page = read_image(sock, magic, identity, 1, False)
        pages.append(page)

    return images, {
        "source": feed,
        "duplex": duplex,
        "job_id": job_id,
        "pages": pages,
        "hardware_status": status,
        "parameters_hex": params.hex(),
    }


def run(args):
    target = str(ipaddress.IPv4Address(args.target))
    local_ip, interface = route_identity(target)
    identity = mac_bytes((Path("/sys/class/net") / interface / "address").read_text().strip())
    search = SimpleNamespace(target=target, local_ip=local_ip,
                             reply_port=REPLY_PORT, timeout=5, retries=3)
    records = discover(search, discovery_request(local_ip, identity))
    record = next((x for x in records if x["peer"][0] == target), None)
    if record is None:
        raise ProtocolError("no discovery reply from target")
    device = record["decoded"]
    if (device["product"].lower() != "scansnap ix1300" or device["red_mode"]
            or device["password_required"]):
        raise ProtocolError("target is not a supported plain-TCP iX1300")
    magic = device["magic"].encode("ascii")
    reserved = False
    scanner = None
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as trigger:
        trigger.bind((local_ip, TRIGGER_PORT))
        try:
            with closing(connect_and_greet(target, device["application_port"], local_ip, magic)) as app:
                app.sendall(reserve_request(magic, identity, local_ip, TRIGGER_PORT,
                                            datetime.now().astimezone()))
                ack = parse_app_ack(read_exact(app, 20), magic, 20)
                if ack["status"] != 0:
                    raise ProtocolError(f"reservation failed with status {ack['status']}")
                reserved = True
            scanner = connect_and_greet(target, device["scanner_port"], local_ip, magic)
            images, metadata = scan_page(
                scanner, magic, identity, args.source, duplex=args.duplex)
            outputs = {}
            base = Path(args.output)
            for side, image in images.items():
                if not image.startswith(b"\xff\xd8"):
                    raise ProtocolError(f"{side} data does not start with a JPEG marker")
                if args.duplex:
                    suffix = base.suffix or ".jpg"
                    output = base.with_name(f"{base.stem}-{side}{suffix}")
                else:
                    output = base
                output.write_bytes(image)
                outputs[side] = {
                    "path": str(output.resolve()),
                    "bytes": len(image),
                    "jpeg_complete": image.endswith(b"\xff\xd9"),
                }
            metadata["outputs"] = outputs
            return metadata
        finally:
            if scanner is not None:
                try:
                    simple_command(scanner, magic, identity, 0xd8, "CANCEL READ")
                except (OSError, ValueError):
                    pass
                try:
                    simple_command(scanner, magic, identity, 0xd6, "END JOB")
                except (OSError, ValueError):
                    pass
                scanner.close()
            if reserved:
                try:
                    with closing(connect_and_greet(target, device["application_port"], local_ip, magic)) as app:
                        app.sendall(release_request(magic, identity))
                        read_exact(app, 16)
                except (OSError, ValueError):
                    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source", choices=("auto", "adf", "card"), default="auto")
    parser.add_argument("--duplex", action="store_true")
    parser.add_argument("--output", default="ix1300-test.jpg")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
