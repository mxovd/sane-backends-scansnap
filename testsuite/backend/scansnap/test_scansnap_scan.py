# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
"""Offline packet tests for the one-page scan probe."""

import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools/scansnap"))
import scansnap_scan as scan


class ScanPacketTests(unittest.TestCase):
    def test_scanner_request_layout(self):
        packet = scan.scanner_request(b"VENS", bytes.fromhex("001122334455"),
                                      b"\xd8\0\0\0\0\0")
        self.assertEqual(len(packet), 64)
        self.assertEqual(struct.unpack_from(">I4sII", packet), (64, b"VENS", 1, 0))
        self.assertEqual(struct.unpack_from(">IIII", packet, 32), (6, 0, 0, 0))
        self.assertEqual(packet[48:54], b"\xd8\0\0\0\0\0")

    def test_fixed_scan_parameters(self):
        adf = scan.scan_parameters("adf")
        card = scan.scan_parameters("card")
        adf_duplex = scan.scan_parameters("adf", duplex=True)
        card_duplex = scan.scan_parameters("card", duplex=True)
        self.assertEqual(len(adf), 80)
        self.assertEqual(adf[:7], bytes([1, 1, 1, 1, 0x80, 1, 0xc1]))
        self.assertEqual(card[:7], bytes([1, 4, 1, 1, 0x80, 1, 0x80]))
        self.assertEqual(adf_duplex[1], 3)
        self.assertEqual(card_duplex[1], 6)
        self.assertEqual(card[28], 0x20)
        self.assertEqual(struct.unpack_from(">HH", adf, 34), (300, 300))
        self.assertEqual(struct.unpack_from(">II", adf, 42), (10368, 17232))
        self.assertEqual(struct.unpack_from(">II", card, 42), (10368, 17424))

    def test_select_feed_requires_exactly_one_path(self):
        idle = {"paper_in_adf": False, "card_loaded": False}
        adf = {"paper_in_adf": True, "card_loaded": False}
        card = {"paper_in_adf": False, "card_loaded": True}
        with self.assertRaises(scan.ProtocolError):
            scan.select_feed(idle, "auto")
        self.assertEqual(scan.select_feed(adf, "auto"), "adf")
        self.assertEqual(scan.select_feed(card, "card"), "card")
        with self.assertRaises(scan.ProtocolError):
            scan.select_feed(card, "adf")

    def test_image_payload_discards_two_control_bytes(self):
        image = bytearray(b"jpeg")
        appended = scan.append_image_payload(image, b"\x12\x34tail")
        self.assertEqual(appended, 4)
        self.assertEqual(image, b"jpegtail")
        with self.assertRaises(scan.ProtocolError):
            scan.append_image_payload(image, b"\x00")


if __name__ == "__main__":
    unittest.main()
