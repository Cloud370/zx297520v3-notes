"""Offline tests only: never opens a real serial port."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import amt


def reply(opcode, payload):
    body = struct.pack("!H", opcode) + payload
    checksum = 0
    for value in body:
        checksum ^= value
    frame = b"\x02" + body + bytes([checksum, 2])
    return struct.pack("<I", len(frame)) + frame


class FakePort:
    def __init__(self, data, fragment=3):
        self.data = bytearray(data)
        self.fragment = fragment
        self.writes = []

    def write(self, data):
        self.writes.append(data)
        return len(data)

    def flush(self):
        pass

    def read(self, size):
        size = min(size, self.fragment, len(self.data))
        data = bytes(self.data[:size])
        del self.data[:size]
        return data


LAYOUT = "\n".join(f'mtd{i}: {size:08x} 00010000 "{name}"'
                   for i, (name, size) in enumerate(amt.PARTITIONS))


class FakeFlash:
    def __init__(self, changing=False, fail_after=None):
        self.counts = {}
        self.changing = changing
        self.fail_after = fail_after
        self.reads = 0

    def shell(self, command):
        if command == b"cat /proc/mtd":
            return LAYOUT.encode()
        amt.encode(0xC1, command)
        part = int(command.split(b"mtd")[1].split(b"ro")[0])
        index = int(command.split(b"skip=")[1].split()[0])
        self.reads += 1
        if self.fail_after is not None and self.reads > self.fail_after:
            raise TimeoutError("simulated disconnect")
        key = (part, index)
        self.counts[key] = self.counts.get(key, 0) + 1
        byte = (part + index) % 256
        if self.changing and key == (0, 0) and self.counts[key] == 2:
            byte ^= 1
        return bytes([byte]) * 1024


class ProtocolTests(unittest.TestCase):
    def test_observed_platform_and_id_vectors(self):
        self.assertEqual(amt.encode(0x1004).hex(), "050000000210041402")
        self.assertEqual(amt.decode(bytes.fromhex("06000000021004011502"), 0x1004), b"\x01")
        self.assertEqual(amt.encode(0xC1, b"id").hex(), "070000000200c16964cc02")

    def test_fragmented_binary_response_preserves_nuls(self):
        payload = bytes(range(256)) * 4
        session = amt.Session(FakePort(reply(0xC1, payload)))
        self.assertEqual(session.exchange(0xC1, b"id"), payload)

    def test_corrupt_or_mismatched_frames(self):
        good = reply(0xC1, b"root\n")
        bad_checksum = bytearray(good)
        bad_checksum[-2] ^= 1
        bad_delimiter = bytearray(good)
        bad_delimiter[-1] = 3
        for packet in (good[:-1], bytes(bad_checksum), bytes(bad_delimiter), reply(0xD1, b"x")):
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                amt.decode(packet, 0xC1)

    def test_rejected_input_never_reaches_transport(self):
        port = FakePort(b"")
        session = amt.Session(port)
        for command in (b"x" * 256, b"id\0", b"id; reboot",
                        b"dd if=/dev/mtd0ro bs=1024 skip=64 count=1 2>/dev/null"):
            with self.assertRaises(ValueError):
                session.exchange(0xC1, command)
        self.assertEqual(port.writes, [])
        with self.assertRaises(ValueError):
            amt.encode(0x1000, b"\x03")

    def test_bad_length_poisoned_session_cannot_send_again(self):
        port = FakePort(struct.pack("<I", 0xFFFFFFFF))
        session = amt.Session(port)
        with self.assertRaises(ValueError):
            session.exchange(0x1004)
        with self.assertRaises(RuntimeError):
            session.exchange(0x1004)
        self.assertEqual(len(port.writes), 1)

    def test_timeout_poisoned_session(self):
        session = amt.Session(FakePort(b""), timeout=0)
        with self.assertRaises(TimeoutError):
            session.exchange(0x1004)
        self.assertTrue(session.failed)

    def test_layout_must_match_exactly(self):
        amt.validate_layout(LAYOUT)
        for other in (LAYOUT.replace("00960000", "07960000"), LAYOUT + '\nmtd6: 00010000 00010000 "extra"'):
            with self.assertRaises(ValueError):
                amt.validate_layout(other)

    def test_hello_matches_device_tested_bytes(self):
        self.assertEqual(len(amt.hello_image()), 139)
        self.assertEqual(hashlib.sha256(amt.hello_image()).hexdigest(),
                         "7784b67b306cecd9b14fbc5b166ce96398bfb2d26123acae1614b6ef83bd2742")
        for command in amt.ALLOWED_SHELL:
            self.assertLessEqual(len(command), 255)
            amt.encode(0xC1, command)

    def test_hello_refuses_to_execute_corrupt_upload(self):
        class BadUpload:
            def __init__(self):
                self.commands = []

            def shell(self, command):
                self.commands.append(command)
                if command == amt.HELLO_CHECK:
                    return b"FREE\n"
                if command == amt.HELLO_READ:
                    return b"corrupt"
                return b"OK\n"

        device = BadUpload()
        with self.assertRaises(RuntimeError):
            amt.hello(device)
        self.assertNotIn(amt.HELLO_RUN, device.commands)


class BackupTests(unittest.TestCase):
    def test_full_dump_and_independent_reread(self):
        with tempfile.TemporaryDirectory() as temporary, patch("builtins.print"):
            folder = Path(temporary) / "backup"
            flash = FakeFlash()
            self.assertEqual(amt.backup(flash, folder), "verified")
            manifest = json.loads((folder / "manifest.json").read_text())
            for part, record in enumerate(manifest["partitions"]):
                data = (folder / record["file"]).read_bytes()
                self.assertEqual(len(data), amt.PARTITIONS[part][1])
                self.assertEqual(data[:1024], bytes([part]) * 1024)
                self.assertEqual(hashlib.sha256(data).hexdigest(), record["second_read_sha256"])
                self.assertTrue(record["verified_identical"])
            self.assertTrue(all(count == 2 for count in flash.counts.values()))

    def test_changed_flash_is_not_reported_verified(self):
        with tempfile.TemporaryDirectory() as temporary, patch("builtins.print"):
            folder = Path(temporary) / "backup"
            self.assertEqual(amt.backup(FakeFlash(changing=True), folder), "dumped_with_changing_partitions")
            record = json.loads((folder / "manifest.json").read_text())["partitions"][0]
            self.assertEqual(record["differing_chunks"], [0])

    def test_disconnect_retains_failed_manifest_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "backup"
            with self.assertRaises(TimeoutError):
                amt.backup(FakeFlash(fail_after=3), folder)
            manifest = (folder / "manifest.json").read_bytes()
            self.assertEqual(json.loads(manifest)["status"], "failed")
            self.assertEqual((folder / "mtd0-zloader.bin").stat().st_size, 3072)
            with self.assertRaises(FileExistsError):
                amt.backup(FakeFlash(), folder)
            self.assertEqual((folder / "manifest.json").read_bytes(), manifest)


if __name__ == "__main__":
    unittest.main()
