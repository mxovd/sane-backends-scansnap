# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
"""Offline protocol fixtures; these are synthetic, not hardware captures."""

import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "scansnap_discover", Path(__file__).resolve().parents[3] / "tools/scansnap/scansnap_discover.py"
)
protocol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protocol)


def reply():
    data = bytearray(148)
    struct.pack_into(">4sHHHHI", data, 0, b"VENS", 0, 0, 16, 48, 1)
    data[16:20] = bytes([192, 0, 2, 20])
    # Illustrative advertised ports, not verified iX1300 default ports.
    struct.pack_into(">II", data, 20, 60000, 60001)
    data[28:34] = bytes.fromhex("001122334455")
    data[36:40] = bytes([12, 2, 0, 3])
    data[40:44] = b"Test"
    data[104:120] = b"ScanSnap iX1300 "
    data[132:142] = b"TEST000001"
    data[144:148] = bytes([0, 1, 64, 16])
    return bytes(data)


class DiscoveryTests(unittest.TestCase):
    def test_tcp_greeting_decoding_and_fragmented_read(self):
        greeting = struct.pack(">I4sII", 16, b"VENS", 0, 0x12345678)
        class FakeSocket:
            def __init__(self):
                self.parts = [greeting[:3], greeting[3:9], greeting[9:]]

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def settimeout(self, timeout):
                self.timeout = timeout

            def recv(self, size):
                return self.parts.pop(0)

        with patch.object(protocol.socket, "create_connection", return_value=FakeSocket()) as connect:
            parsed = protocol.read_greeting("192.0.2.20", 53218, "192.0.2.10", b"VENS", 3)
        connect.assert_called_once_with(
            ("192.0.2.20", 53218), timeout=3, source_address=("192.0.2.10", 0))
        self.assertEqual(parsed["status"], 0)
        self.assertEqual(parsed["trailer_hex"], "12345678")

    def test_tcp_greeting_rejects_wrong_magic(self):
        with self.assertRaisesRegex(ValueError, "differs from discovery"):
            protocol.parse_greeting(struct.pack(">I4sII", 16, b"SSEN", 0, 0), b"VENS")

    def test_route_identity_uses_selected_source_and_interface(self):
        route = '[{"dst":"192.0.2.20","dev":"wlan0","prefsrc":"192.0.2.10"}]'
        with patch.object(protocol.subprocess, "check_output", return_value=route) as run:
            self.assertEqual(protocol.route_identity("192.0.2.20"),
                             ("192.0.2.10", "wlan0"))
        run.assert_called_once_with(
            ["ip", "-j", "-4", "route", "get", "192.0.2.20"],
            text=True, stderr=protocol.subprocess.PIPE,
        )

    def test_route_identity_rejects_missing_source(self):
        with patch.object(protocol.subprocess, "check_output",
                          return_value='[{"dev":"wlan0"}]'):
            with self.assertRaisesRegex(ValueError, "lacks source address"):
                protocol.route_identity("192.0.2.20")

    def test_request_wire_bytes(self):
        expected = bytes.fromhex(
            "56454e53 00000000 c000020a 001122334455 0000 "
            "0000d7ea 0010 0000 00000000"
        )
        self.assertEqual(protocol.discovery_request(
            "192.0.2.10", bytes.fromhex("001122334455")), expected)

    def test_ix1300_identity_ports_and_flags(self):
        parsed = protocol.discovery_reply(reply())
        self.assertEqual(parsed["product"], "ScanSnap iX1300")
        self.assertEqual(parsed["ip"], "192.0.2.20")
        self.assertEqual(parsed["scanner_port"], 60000)
        self.assertEqual(parsed["application_port"], 60001)
        self.assertEqual(parsed["serial"], "TEST000001")
        self.assertTrue(parsed["red_mode"])
        self.assertTrue(parsed["connection_encrypted_flag"])
        self.assertEqual(parsed["occupied_status"], 3)
        self.assertEqual(parsed["device_occupancy_state"], 1)
        self.assertEqual(parsed["profile_setting_state"], 64)

    def test_truncated_required_fields(self):
        for length in range(144):
            with self.subTest(length=length), self.assertRaises(ValueError):
                protocol.discovery_reply(reply()[:length])
        with self.assertRaises(ValueError):
            protocol.discovery_reply(reply()[:145])

    def test_optional_fields_and_unknown_tail(self):
        for length in (144, 146, 147, 148):
            self.assertEqual(protocol.discovery_reply(reply()[:length])["serial"], "TEST000001")
        self.assertEqual(protocol.discovery_reply(reply() + b"\xaa\xbb")["unparsed_tail_hex"], "aabb")

    def test_invalid_magic_status_and_keepalive(self):
        for offset, value in ((0, b"NOPE"), (4, b"\x80\x01"), (6, b"\x00\x01")):
            data = bytearray(reply())
            data[offset:offset + len(value)] = value
            with self.assertRaises(ValueError):
                protocol.discovery_reply(data)

    def test_legacy_reply_without_serial(self):
        data = bytearray(reply()[:132])
        struct.pack_into(">H", data, 8, 5)
        data[36:40] = bytes([8, 0, 0, 2])
        parsed = protocol.discovery_reply(data)
        self.assertTrue(parsed["red_mode"])
        self.assertIsNone(parsed["occupied_status"])
        self.assertNotIn("serial", parsed)

    def test_invalid_request_inputs(self):
        for ip, mac, port in (("0.0.0.0", b"123456", 55274),
                              ("192.0.2.1", b"12345", 55274),
                              ("192.0.2.1", b"123456", 65536)):
            with self.assertRaises(ValueError):
                protocol.discovery_request(ip, mac, port)
        with self.assertRaises(ValueError):
            protocol.mac_bytes("00:11:22:33:44")


if __name__ == "__main__":
    unittest.main()
