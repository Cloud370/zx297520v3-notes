"""Small AMT client for the firmware documented in README.md; no flash writer.

Python 3.10+, pyserial. Uses an explicitly selected Windows ZTE AT serial port.
The public CLI is a cleaned-up derivative, not a separately device-tested release.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import time


VERSION = b"7520V3SCV2.01.01.02P38-MIFI_MIN_SV6158_DCXO"
PARTITIONS = (
    ("zloader", 0x10000), ("nvrofs", 0x80000), ("uboot", 0x40000),
    ("imagefs", 0x460000), ("rootfs", 0x960000), ("userdata", 0x170000),
)
QUERIES = (
    b"id",
    b"uname -a; cat /proc/cpuinfo; echo DONE",
    b"cat /proc/mtd",
    b"cat /proc/cmdline; echo DONE",
    b"cat /proc/meminfo | head -8; echo DONE",
    b"cat /proc/iomem; echo DONE",
)
HELLO_PATH = "/tmp/zx-amt-hello"


def hello_image():
    """Generate the 139-byte ARM EABI5 ELF used in the experiment.

    ARM instructions: write(1, message, 23); exit(0). No libc or floating point.
    The ADR at 0x10058 uses PC=0x10060, message=0x10074, hence offset 0x14.
    """
    message = b"ARM binary executed OK\n"
    instructions = struct.pack(
        "<8I", 0xE3A00001, 0xE28F1014, 0xE3A02000 | len(message),
        0xE3A07004, 0xEF000000, 0xE3A00000, 0xE3A07001, 0xEF000000,
    )
    size = 84 + len(instructions) + len(message)
    header = struct.pack(
        "<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + bytes(9),
        2, 40, 1, 0x10054, 52, 0, 0x05000200, 52, 32, 1, 0, 0, 0,
    )
    segment = struct.pack("<8I", 1, 0, 0x10000, 0x10000, size, size, 5, 4096)
    return header + segment + instructions + message


def hello_upload_commands():
    image = hello_image()
    commands = []
    for offset in range(0, len(image), 32):
        octal = "".join(f"\\{byte:03o}" for byte in image[offset:offset + 32])
        redirect = ">" if offset == 0 else ">>"
        commands.append(f"printf '{octal}' {redirect} {HELLO_PATH}; echo OK".encode())
    return tuple(commands)


HELLO_CHECK = f"test -e {HELLO_PATH} && echo EXISTS || echo FREE".encode()
HELLO_READ = f"dd if={HELLO_PATH} bs=139 count=1 2>/dev/null".encode()
HELLO_RUN = f"chmod 700 {HELLO_PATH}; {HELLO_PATH}; echo RC:$?".encode()
HELLO_REMOVE = f"rm -f {HELLO_PATH}; echo REMOVED".encode()
ALLOWED_SHELL = frozenset(QUERIES + hello_upload_commands() + (
    HELLO_CHECK, HELLO_READ, HELLO_RUN, HELLO_REMOVE,
))


def encode(opcode, payload=b""):
    """Encode only the operations exposed by this tool, with the 255-byte guard."""
    allowed = opcode in (0x1004, 0x00D1) and payload == b""
    allowed |= opcode == 0x1000 and payload == b"\x00"
    if opcode == 0x00C1:
        if len(payload) > 255 or b"\0" in payload:
            raise ValueError("AMT shell payload must be <=255 bytes and contain no NUL")
        chunk = re.fullmatch(
            rb"dd if=/dev/mtd([0-5])ro bs=1024 skip=([0-9]+) count=1 2>/dev/null",
            payload,
        )
        allowed = payload in ALLOWED_SHELL or bool(
            chunk and int(chunk[2]) < PARTITIONS[int(chunk[1])][1] // 1024
        )
    if not allowed:
        raise ValueError("Operation is outside this client's fixed command set")
    body = struct.pack("!H", opcode) + payload
    checksum = 0
    for byte in body:
        checksum ^= byte
    frame = b"\x02" + body + bytes([checksum, 2])
    return struct.pack("<I", len(frame)) + frame


def decode(packet, expected_opcode):
    if len(packet) < 9:
        raise ValueError("Incomplete AMT packet")
    length, = struct.unpack_from("<I", packet)
    if not 5 <= length <= 2053 or len(packet) != length + 4:
        raise ValueError("Invalid AMT response length")
    frame = packet[4:]
    checksum = 0
    for byte in frame[1:-1]:
        checksum ^= byte
    if (frame[0] != 2 or frame[-1] != 2 or checksum
            or int.from_bytes(frame[1:3], "big") != expected_opcode):
        raise ValueError("Invalid AMT delimiters, checksum or response opcode")
    return frame[3:-2]


class Session:
    def __init__(self, port, timeout=10):
        self.port = port
        self.timeout = timeout
        self.failed = False

    def exchange(self, opcode, payload=b""):
        if self.failed:
            raise RuntimeError("Session is unusable after a transport/framing error")
        packet = encode(opcode, payload)  # Reject unsafe input before any USB write.
        end = time.monotonic() + self.timeout

        def exact(size):
            data = bytearray()
            while len(data) < size and time.monotonic() < end:
                data.extend(self.port.read(size - len(data)))
            if len(data) != size:
                raise TimeoutError("Incomplete reply; stop, do not send another command")
            return bytes(data)

        try:
            if self.port.write(packet) != len(packet):
                raise OSError("Short serial write")
            self.port.flush()
            header = exact(4)
            length, = struct.unpack("<I", header)
            if not 5 <= length <= 2053:
                raise ValueError("Invalid response length; framing may be lost")
            return decode(header + exact(length), opcode)
        except Exception:
            self.failed = True
            raise

    def shell(self, command):
        result = self.exchange(0xC1, command)
        if len(result) >= 2047:
            raise RuntimeError("Output may be truncated; use smaller queries")
        return result


def validate_layout(text):
    actual = re.findall(r'mtd([0-9]+): ([0-9a-fA-F]+) ([0-9a-fA-F]+) "([^"]+)"', text)
    actual = [(int(i), int(size, 16), int(erase, 16), name)
              for i, size, erase, name in actual]
    expected = [(i, size, 0x10000, name) for i, (name, size) in enumerate(PARTITIONS)]
    if actual != expected:
        raise ValueError("MTD layout differs from the documented 16 MiB SPI NOR device")


def read_chunk(session, part, index):
    command = f"dd if=/dev/mtd{part}ro bs=1024 skip={index} count=1 2>/dev/null".encode()
    data = session.shell(command)
    if len(data) != 1024:
        raise ValueError(f"Short MTD read at partition {part}, chunk {index}")
    return data


def backup(session, output):
    layout = session.shell(b"cat /proc/mtd").decode("ascii")
    validate_layout(layout)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"status": "running", "version": VERSION.decode(), "partitions": [],
                "note": "Current-state dump; not necessarily untouched factory firmware."}

    def save():
        temporary = output / "manifest.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        temporary.replace(output / "manifest.json")

    save()
    try:
        for part, (name, size) in enumerate(PARTITIONS):
            record = {"part": part, "name": name, "size": size,
                      "file": f"mtd{part}-{name}.bin"}
            manifest["partitions"].append(record)
            save()
            digest = hashlib.sha256()
            with (output / record["file"]).open("xb") as target:
                for index in range(size // 1024):
                    data = read_chunk(session, part, index)
                    target.write(data)
                    digest.update(data)
            record["sha256"] = digest.hexdigest()
            save()
            print(f"Dumped {name}: {size} bytes", flush=True)
        for record in manifest["partitions"]:
            digest = hashlib.sha256()
            differences = []
            with (output / record["file"]).open("rb") as target:
                for index in range(record["size"] // 1024):
                    data = read_chunk(session, record["part"], index)
                    digest.update(data)
                    if target.read(1024) != data:
                        differences.append(index)
            record["second_read_sha256"] = digest.hexdigest()
            record["differing_chunks"] = differences
            record["verified_identical"] = not differences
            save()
            print(f"Verified {record['name']}: {not differences}", flush=True)
        manifest["status"] = ("verified" if all(
            r["verified_identical"] for r in manifest["partitions"]
        ) else "dumped_with_changing_partitions")
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = repr(error)
        raise
    finally:
        save()
    return manifest["status"]


def hello(session):
    if session.shell(HELLO_CHECK) != b"FREE\n":
        raise RuntimeError(f"{HELLO_PATH} already exists; not overwriting it")
    for command in hello_upload_commands():
        if session.shell(command) != b"OK\n":
            raise RuntimeError("Unexpected upload response")
    if session.shell(HELLO_READ) != hello_image():
        raise RuntimeError("Uploaded ELF differs; refusing to execute it")
    result = session.shell(HELLO_RUN)
    print(result.decode("ascii"), end="")
    if result != b"ARM binary executed OK\nRC:0\n":
        raise RuntimeError("ELF execution was not verified")
    if session.shell(HELLO_REMOVE) != b"REMOVED\n":
        raise RuntimeError("Could not confirm temporary-file cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Explicit AT port, e.g. COM9")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("probe", help="Read identity, root id, memory and MTD layout")
    actions.add_parser("hello", help="Upload/verify/run the fixed tiny ELF in /tmp")
    actions.add_parser("recover", help="Write normal NEXT-BOOT mode; does not reboot")
    actions.add_parser("backup", help="Dump documented NOR layout twice").add_argument("output")
    args = parser.parse_args()
    try:
        import serial
        from serial.tools import list_ports
    except ImportError:
        parser.error("Install pyserial: python -m pip install pyserial==3.5")
    matches = [p for p in list_ports.comports() if p.device == args.port
               and p.vid == 0x19D2 and p.pid == 0x0201
               and p.description.startswith("AT Interface")]
    if len(matches) != 1:
        parser.error("Expected a Windows 19d2:0201 AT Interface; do not select LOG/another modem")
    try:
        with serial.Serial(args.port, 115200, timeout=.2, write_timeout=3) as port:
            session = Session(port)
            if session.exchange(0x1004) != b"\x01":
                raise ValueError("Unexpected platform response")
            version = session.exchange(0xD1).rstrip(b"\0")
            print("Version:", version.decode("ascii", errors="replace"))
            if version != VERSION:
                raise ValueError("Untested firmware; no shell command or mode write sent")
            if args.action == "probe":
                for command in QUERIES:
                    print("$", command.decode())
                    print(session.shell(command).decode(errors="replace"), end="")
            elif args.action == "backup":
                return 0 if backup(session, args.output) == "verified" else 2
            elif args.action == "hello":
                hello(session)
            elif args.action == "recover":
                if session.exchange(0x1000, b"\x00") != bytes(4):
                    raise RuntimeError("Normal next-boot mode was not confirmed")
                print("Normal next-boot flag acknowledged. Not rebooted; verify after power cycle.")
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
