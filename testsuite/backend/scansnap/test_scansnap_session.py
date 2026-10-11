# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
"""Offline iX1300 session packet and cleanup checks."""

from datetime import datetime, timezone, timedelta
from io import BytesIO
import struct
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools/scansnap"))
import scansnap_session as session


MAGIC = b"VENS"
IDENTITY = bytes.fromhex("001122334455")
def fixture(name):
    return bytes.fromhex((Path(__file__).with_name("fixtures") / name).read_text())


LIVE_VPD = fixture("vpd.hex")
LIVE_HARDWARE_IDLE = fixture("hardware_idle.hex")
LIVE_HARDWARE_ADF = fixture("hardware_adf.hex")
LIVE_HARDWARE_RETURN = fixture("hardware_return.hex")


class FakeSocket:
    def __init__(self, data=b"", error=None):
        self.stream = BytesIO(data)
        self.error = error
        self.sent = []
        self.closed = False

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if self.error:
            raise self.error
        return self.stream.read(size)

    def bind(self, address):
        self.bound = address

    def close(self):
        self.closed = True


class SessionTests(unittest.TestCase):
    def test_reserve_release_and_inquiry_wire_layout(self):
        now = datetime(2026, 10, 11, 9, 8, 7, tzinfo=timezone(timedelta(hours=9)))
        reserve = session.reserve_request(MAGIC, IDENTITY, "192.0.2.10", 55275, now)
        self.assertEqual(len(reserve), 128)
        self.assertEqual(struct.unpack_from(">I4sII", reserve), (128, MAGIC, 17, 0))
        self.assertEqual(reserve[16:22], IDENTITY)
        self.assertEqual(struct.unpack_from(">HBBII", reserve, 32), (16, 30, 0, 1, 0))
        self.assertEqual(reserve[44:48], bytes([192, 0, 2, 10]))
        self.assertEqual(struct.unpack_from(">I", reserve, 48)[0], 55275)
        self.assertEqual(reserve[52:100], bytes(48))
        self.assertEqual(struct.unpack_from(">II", reserve, 100),
                         ((2026 << 16) | (10 << 8) | 11,
                          (9 << 24) | (8 << 16) | (7 << 8)))
        self.assertEqual(struct.unpack_from(">i", reserve, 116)[0], -9 * 3600)
        release = session.release_request(MAGIC, IDENTITY)
        self.assertEqual(len(release), 32)
        self.assertEqual(struct.unpack_from(">I4sII", release), (32, MAGIC, 18, 0))
        self.assertEqual(struct.unpack_from(">I", release, 24)[0], 1)
        inquiry = session.inquiry_request(MAGIC, IDENTITY)
        self.assertEqual(len(inquiry), 64)
        self.assertEqual(struct.unpack_from(">I4sII", inquiry), (64, MAGIC, 1, 0))
        self.assertEqual(struct.unpack_from(">IIII", inquiry, 32), (6, 96, 0, 0))
        self.assertEqual(inquiry[48:54], b"\x12\x00\x00\x00\x60\x00")
        vpd = session.inquiry_request(MAGIC, IDENTITY, vpd=True)
        self.assertEqual(struct.unpack_from(">IIII", vpd, 32), (6, 144, 0, 0))
        self.assertEqual(vpd[48:54], b"\x12\x01\xf0\x00\x90\x00")

    def test_inquiry_reply_decodes_identity(self):
        payload = bytearray(96)
        payload[8:16] = b"RICOH   "
        payload[16:32] = b"ScanSnap iX1300 "
        payload[32:36] = b"1A00"
        header = struct.pack(">I4sii24x", 136, MAGIC, 0, 0)
        parsed = session.parse_inquiry_reply(header, payload, MAGIC)
        self.assertEqual(parsed["vendor"], "RICOH")
        self.assertEqual(parsed["product"], "ScanSnap iX1300")
        self.assertEqual(parsed["revision"], "1A00")

    def test_live_vpd_decodes_conservative_capabilities(self):
        decoded = session.decode_vpd_f0(LIVE_VPD)
        self.assertEqual(decoded["page_length"], 0x8b)
        self.assertEqual(decoded["basic_resolution_dpi"], {"x": 600, "y": 600})
        self.assertEqual(decoded["maximum_resolution_dpi"], {"x": 600, "y": 600})
        self.assertEqual(decoded["minimum_resolution_dpi"], {"x": 50, "y": 50})
        self.assertIn(300, decoded["standard_resolutions_dpi"])
        self.assertTrue(decoded["sources"]["adf"])
        self.assertTrue(decoded["sources"]["duplex"])
        self.assertTrue(decoded["sources"]["operator_panel"])
        self.assertFalse(decoded["sources"]["flatbed"])
        self.assertEqual(decoded["buffer_bytes"], 0x16e00000)
        self.assertTrue(decoded["legacy_commands"]["read"])
        self.assertTrue(decoded["legacy_commands"]["set_window"])
        self.assertTrue(decoded["legacy_commands"]["scan"])
        self.assertTrue(decoded["legacy_commands"]["inquiry"])
        self.assertTrue(decoded["extended"]["start_job"])
        self.assertTrue(decoded["extended"]["return_path"])

    def test_hardware_status_wire_layout_and_decode(self):
        request = session.hardware_status_request(MAGIC, IDENTITY)
        self.assertEqual(len(request), 64)
        self.assertEqual(struct.unpack_from(">IIII", request, 32), (10, 32, 0, 0))
        self.assertEqual(request[48:58], b"\xc2\0\0\0\0\0\0\0\x20\0")
        payload = bytearray(32)
        payload[3] = 0x20
        payload[4] = 0x01
        payload[7] = 0x55
        payload[15] = 0x20
        decoded = session.decode_hardware_status(payload)
        self.assertTrue(decoded["adf_cover_open"])
        self.assertTrue(decoded["scan_button"])
        self.assertTrue(decoded["multi_feed_overlap"])
        self.assertTrue(decoded["continuous_feed"])

    def test_live_idle_hardware_status(self):
        decoded = session.decode_hardware_status(LIVE_HARDWARE_IDLE)
        self.assertTrue(decoded["hopper_empty"])
        self.assertFalse(decoded["paper_in_adf"])
        self.assertFalse(decoded["card_loaded"])
        self.assertTrue(decoded["wifi_switch"])
        self.assertTrue(decoded["wifi_in_use"])
        self.assertEqual(decoded["wifi_state_bits"], 0xc0)
        self.assertEqual(decoded["device_error_code"], 0)

    def test_live_loaded_hardware_statuses(self):
        adf = session.decode_hardware_status(LIVE_HARDWARE_ADF)
        self.assertTrue(adf["paper_in_adf"])
        self.assertFalse(adf["card_loaded"])
        self.assertFalse(adf["top"])
        return_path = session.decode_hardware_status(LIVE_HARDWARE_RETURN)
        self.assertFalse(return_path["paper_in_adf"])
        self.assertTrue(return_path["card_loaded"])
        self.assertTrue(return_path["top"])

    def test_failed_inquiry_still_releases_reservation(self):
        reserve_ack = struct.pack(">I4siH6x", 20, MAGIC, 0, 16)
        release_ack = struct.pack(">I4siI", 16, MAGIC, 0, 0)
        app_reserve = FakeSocket(reserve_ack)
        scanner = FakeSocket(error=OSError("inquiry read failed"))
        app_release = FakeSocket(release_ack)
        trigger = FakeSocket()
        record = {"peer": ["192.0.2.20", 52217], "decoded": {
            "ip": "192.0.2.20", "magic": "VENS", "interface_version": 16,
            "host_type": 48, "product": "ScanSnap iX1300", "red_mode": False,
            "password_required": False, "application_port": 53219,
            "scanner_port": 53218,
        }}
        with patch.object(session, "route_identity", return_value=("192.0.2.10", "wlan0")), \
             patch.object(session.Path, "read_text", return_value="00:11:22:33:44:55"), \
             patch.object(session, "discover", return_value=[record]), \
             patch.object(session, "connect_and_greet",
                          side_effect=[app_reserve, scanner, app_release]), \
             patch.object(session.socket, "socket", return_value=trigger):
            result = session.probe(type("Args", (), {"target": "192.0.2.20"})())
        self.assertIn("inquiry read failed", result["error"])
        self.assertEqual(result["release"]["status"], 0)
        self.assertEqual(struct.unpack_from(">I", app_release.sent[0], 8)[0], 18)
        self.assertTrue(trigger.closed)

    def test_two_inquiries_then_release(self):
        reserve_ack = struct.pack(">I4siH6x", 20, MAGIC, 0, 16)
        release_ack = struct.pack(">I4siI", 16, MAGIC, 0, 0)
        app_reserve = FakeSocket(reserve_ack)
        standard_payload = bytearray(96)
        standard_payload[8:16] = b"FUJITSU "
        standard_payload[16:32] = b"ScanSnap iX1300 "
        standard_payload[32:36] = b"0M00"
        standard = FakeSocket(struct.pack(">I4sii24x", 136, MAGIC, 0, 0)
                              + standard_payload)
        vpd_payload = LIVE_VPD
        vpd = FakeSocket(struct.pack(">I4sii24x", 184, MAGIC, 0, 0) + vpd_payload)
        hardware_payload = bytes(32)
        hardware = FakeSocket(struct.pack(">I4sii24x", 72, MAGIC, 0, 0)
                              + hardware_payload)
        app_release = FakeSocket(release_ack)
        trigger = FakeSocket()
        record = {"peer": ["192.0.2.20", 52217], "decoded": {
            "ip": "192.0.2.20", "magic": "VENS", "interface_version": 16,
            "host_type": 48, "product": "ScanSnap iX1300", "red_mode": False,
            "password_required": False, "application_port": 53219,
            "scanner_port": 53218,
        }}
        with patch.object(session, "route_identity", return_value=("192.0.2.10", "wlan0")), \
             patch.object(session.Path, "read_text", return_value="00:11:22:33:44:55"), \
             patch.object(session, "discover", return_value=[record]), \
             patch.object(session, "connect_and_greet",
                          side_effect=[app_reserve, standard, vpd, hardware, app_release]), \
             patch.object(session.socket, "socket", return_value=trigger):
            result = session.probe(type("Args", (), {"target": "192.0.2.20"})())
        self.assertNotIn("error", result)
        self.assertEqual(result["inquiry"]["revision"], "0M00")
        self.assertEqual(len(bytes.fromhex(result["vpd_f0"]["payload_hex"])), 144)
        self.assertEqual(standard.sent[0][48:54], b"\x12\x00\x00\x00\x60\x00")
        self.assertEqual(vpd.sent[0][48:54], b"\x12\x01\xf0\x00\x90\x00")
        self.assertEqual(hardware.sent[0][48], 0xc2)
        self.assertEqual(result["hardware_status"]["decoded"]["device_error_code"], 0)
        self.assertEqual(result["release"]["status"], 0)


if __name__ == "__main__":
    unittest.main()
