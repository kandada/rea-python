"""Shared synthetic fixtures for REA-Python tests.

Builders produce small, self-contained binaries so provider tests do not depend
on a compiler, toolchain, or the host platform.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest


def build_elf(sections: dict[str, bytes], *, machine: int = 0x3E, elf_type: int = 2) -> bytes:
    """Build a minimal but structurally valid ELF64 LE with named sections."""

    ehdr_size = 64
    shentsize = 64
    ordered = list(sections.items())
    # Build the section header string table.
    names = ["", *[name for name, _ in ordered], ".shstrtab"]
    shstrtab = bytearray()
    name_offsets: dict[str, int] = {}
    for name in names:
        if name in name_offsets:
            continue
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode() + b"\x00"

    # Lay out section payloads after the ELF header.
    payload = bytearray()
    offsets: list[int] = []
    for _name, data in ordered:
        offsets.append(ehdr_size + len(payload))
        payload += data
    shstrtab_offset = ehdr_size + len(payload)
    payload += shstrtab

    shoff = ehdr_size + len(payload)
    shnum = 1 + len(ordered) + 1  # null + sections + shstrtab
    shstrndx = shnum - 1

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        elf_type,  # e_type
        machine,  # e_machine
        1,  # e_version
        0x1000,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        ehdr_size,  # e_ehsize
        0,  # e_phentsize
        0,  # e_phnum
        shentsize,  # e_shentsize
        shnum,  # e_shnum
        shstrndx,  # e_shstrndx
    )

    headers = bytearray()
    # Null section header.
    headers += _elf_section_header(0, 0, 0, 0, 0, 0, 0, 0)
    for index, (name, data) in enumerate(ordered):
        headers += _elf_section_header(name_offsets[name], 1, 0, offsets[index], len(data), 0, 0, 0)
    headers += _elf_section_header(
        name_offsets[".shstrtab"], 3, 0, shstrtab_offset, len(shstrtab), 0, 0, 0
    )

    return bytes(ehdr) + bytes(payload) + bytes(headers)


def _elf_section_header(
    name: int, type_: int, flags: int, offset: int, size: int, link: int, info: int, entsize: int
) -> bytes:
    return struct.pack("<IIQQQQIIQQ", name, type_, flags, 0, offset, size, link, info, 1, entsize)


def build_pe(
    *,
    machine: int = 0x8664,
    dll_characteristics: int = 0x0160,
    clr: bool = False,
    clr_rva: int = 0x2000,
    metadata_blob: bytes | None = None,
    resource_blob: bytes | None = None,
    method_body: bytes | None = None,
) -> bytes:
    """Build a minimal PE32+ image. Optionally embed a CLI header + metadata."""

    text_rva = 0x1000
    section_raw = 0x200
    resource_rva = 0x1800
    text = bytearray(b"\x90" * 0x200)

    if method_body is not None:
        method_offset = METHOD_RVA - text_rva
        needed = method_offset + len(method_body)
        if len(text) < needed:
            text.extend(b"\x00" * (needed - len(text)))
        text[method_offset : method_offset + len(method_body)] = method_body

    if clr and metadata_blob is not None:
        cli_offset = clr_rva - text_rva
        metadata_rva = clr_rva + 0x40
        meta_offset = metadata_rva - text_rva
        needed = meta_offset + len(metadata_blob)
        if len(text) < needed:
            text.extend(b"\x00" * (needed - len(text)))
        cli_header = struct.pack(
            "<IHHIIII", 72, 2, 5, metadata_rva, len(metadata_blob), 1, 0
        ) + struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        text[cli_offset : cli_offset + len(cli_header)] = cli_header
        text[meta_offset : meta_offset + len(metadata_blob)] = metadata_blob

    if resource_blob is not None:
        resource_offset = resource_rva - text_rva
        needed = resource_offset + len(resource_blob)
        if len(text) < needed:
            text.extend(b"\x00" * (needed - len(text)))
        text[resource_offset : resource_offset + len(resource_blob)] = resource_blob

    optional = bytearray()
    optional += struct.pack("<HBB", 0x20B, 14, 0)
    optional += struct.pack("<IIII", len(text), 0, 0, 0x1000)
    optional += struct.pack("<I", 0x1000)
    optional += struct.pack("<Q", 0x140000000)
    optional += struct.pack("<II", 0x1000, 0x200)
    optional += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    optional += struct.pack("<III", 0, len(text) + 0x1000, section_raw)
    optional += struct.pack("<I", 0)
    optional += struct.pack("<HH", 3, dll_characteristics)
    optional += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    optional += struct.pack("<II", 0, 16)

    data_directories = bytearray()
    for index in range(16):
        if clr and index == 14:
            data_directories += struct.pack("<II", clr_rva, 72)
        elif resource_blob is not None and index == 2:
            data_directories += struct.pack("<II", resource_rva, len(resource_blob))
        else:
            data_directories += struct.pack("<II", 0, 0)

    size_opt = len(optional) + len(data_directories)
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, size_opt, 0x0022)
    pe_header = b"PE\x00\x00" + coff + bytes(optional) + bytes(data_directories)

    e_lfanew = 0x40
    dos = bytearray(b"\x00" * e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    section_header = b".text".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", len(text), text_rva, len(text), section_raw, 0, 0, 0, 0, 0x60000020
    )
    headers = (bytes(dos) + pe_header + section_header).ljust(section_raw, b"\x00")
    return headers + bytes(text)


def build_macho(
    *,
    cpu_type: int = 0x01000007,
    filetype: int = 2,
    flags: int = 0x00200085,
    ncmds: int = 0,
) -> bytes:
    """Build a minimal 64-bit little-endian Mach-O header."""

    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        cpu_type,
        3,
        filetype,
        ncmds,
        0,
        flags,
        0,
    )
    return header


def build_macho_with_exports(symbol: str = "main") -> bytes:
    """Build a 64-bit Mach-O whose LC_DYLD_INFO_ONLY export trie exposes ``symbol``."""

    cmd_size = 48
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, cmd_size, 0, 0)
    edge = symbol.encode() + b"\x00"
    child_offset = 1 + 1 + len(edge) + 1  # terminal_size + child_count + edge + child ULEB
    trie = bytearray()
    trie += bytes([0x00, 0x01]) + edge + bytes([child_offset])
    trie += bytes([0x03, 0x00, 0x80, 0x20, 0x00])  # terminal: flags=0, addr=0x1000
    export_off = len(header) + cmd_size
    command = struct.pack(
        "<IIIIIIIIIIII", 0x80000022, cmd_size, 0, 0, 0, 0, 0, 0, 0, 0, export_off, len(trie)
    )
    return header + command + bytes(trie)


def build_go_binary() -> bytes:
    elf = build_elf({".text": b"\x90" * 16})
    buildinfo = (
        b"\xff Go buildinf:"
        + bytes([8, 2])
        + b"\x00" * 16
        + b"go1.22.3\x00"
        + b"\npath\texample.com/app\n"
        + b"mod\texample.com/app\tv1.0.0\th1:abcdef\n"
        + b"dep\tgithub.com/pkg/errors\tv0.9.1\th1:xyz\n"
        + b"build\t-ldflags\t-s -w\n"
    )
    return elf + buildinfo


def build_rust_binary() -> bytes:
    import json
    import zlib

    payload = json.dumps(
        {
            "packages": [
                {"name": "app", "version": "0.1.0", "source": "local"},
                {
                    "name": "serde",
                    "version": "1.0.200",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
            ],
            "root": 0,
        }
    ).encode()
    section = zlib.compress(payload)
    return build_elf({".text": b"\x90" * 16, ".dep-v0": section})


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


METHOD_RVA = 0x1400


def metadata_blob(
    runtime_version: str = "v4.0.30319",
    *,
    type_name: str = "MyType",
    namespace: str = "MyNamespace",
    method_name: str = "MyMethod",
) -> bytes:
    """Build a CLI metadata blob with one TypeDef and one MethodDef."""

    strings = bytearray(b"\x00")
    indices: dict[str, int] = {}

    def string_index(value: str) -> int:
        if value not in indices:
            indices[value] = len(strings)
            strings.extend(value.encode() + b"\x00")
        return indices[value]

    type_index = string_index(type_name)
    namespace_index = string_index(namespace)
    method_index = string_index(method_name)

    valid = (1 << 0x02) | (1 << 0x06)  # TypeDef + MethodDef
    tables = bytearray()
    tables += struct.pack("<I", 0)  # reserved
    tables += struct.pack("<BBBB", 2, 0, 0, 1)  # major, minor, heap_sizes, reserved
    tables += struct.pack("<Q", valid)
    tables += struct.pack("<Q", 0)  # sorted
    tables += struct.pack("<I", 1)  # TypeDef rows
    tables += struct.pack("<I", 1)  # MethodDef rows
    # TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList
    tables += struct.pack("<IHHHHH", 0, type_index, namespace_index, 0, 0, 1)
    # MethodDef: RVA, ImplFlags, Flags, Name, Signature, ParamList
    tables += struct.pack("<IHHHHH", METHOD_RVA, 0, 0, method_index, 0, 0)

    version = _pad4(runtime_version.encode() + b"\x00")
    us = bytes([0]) + bytes([10]) + "hello".encode("utf-16-le")
    streams = [("#~", bytes(tables)), ("#Strings", bytes(strings)), ("#US", us)]

    root = bytearray(b"BSJB")
    root += struct.pack("<HHII", 1, 1, 0, len(version))
    root += version
    root += struct.pack("<HH", 0, len(streams))

    headers = bytearray()
    data = bytearray()
    offset = len(root) + sum(8 + len(_pad4(name.encode() + b"\x00")) for name, _ in streams)
    for name, payload in streams:
        headers += struct.pack("<II", offset, len(payload)) + _pad4(name.encode() + b"\x00")
        data += payload
        offset += len(payload)
    return bytes(root) + bytes(headers) + bytes(data)


@pytest.fixture
def elf_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.elf"
    path.write_bytes(build_elf({".text": b"\x90" * 32}))
    return path


@pytest.fixture
def pe_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(build_pe())
    return path


@pytest.fixture
def macho_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.macho"
    path.write_bytes(build_macho())
    return path


@pytest.fixture
def macho_exports_file(tmp_path: Path) -> Path:
    path = tmp_path / "exports.macho"
    path.write_bytes(build_macho_with_exports("main"))
    return path


@pytest.fixture
def go_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.go"
    path.write_bytes(build_go_binary())
    return path


@pytest.fixture
def rust_file(tmp_path: Path) -> Path:
    path = tmp_path / "sample.rust"
    path.write_bytes(build_rust_binary())
    return path


@pytest.fixture
def pe_clr_file(tmp_path: Path) -> Path:
    path = tmp_path / "managed.exe"
    body = bytes(
        [
            0x2E,  # tiny header, code size 11
            0x72,
            0x01,
            0x00,
            0x00,
            0x70,  # ldstr 0x70000001
            0x28,
            0x01,
            0x00,
            0x00,
            0x06,  # call 0x06000001
            0x2A,  # ret
        ]
    )
    path.write_bytes(build_pe(clr=True, metadata_blob=metadata_blob(), method_body=body))
    return path


@pytest.fixture
def sqlite_file(tmp_path: Path) -> Path:
    import sqlite3

    path = tmp_path / "sample.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
    connection.execute("CREATE INDEX idx_users_name ON users(name)")
    connection.execute("CREATE VIEW v_users AS SELECT id FROM users")
    connection.execute("INSERT INTO users (name) VALUES ('ada'), ('grace')")
    connection.commit()
    connection.close()
    return path


@pytest.fixture
def zip_file(tmp_path: Path) -> Path:
    import zipfile

    path = tmp_path / "sample.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.txt", "hello")
        archive.writestr("dir/b.txt", "world")
    return path


@pytest.fixture
def apk_file(tmp_path: Path) -> Path:
    import zipfile

    path = tmp_path / "sample.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        archive.writestr("res/values/strings.xml", "<resources/>")
    return path


@pytest.fixture
def flutter_apk_file(tmp_path: Path) -> Path:
    import zipfile

    path = tmp_path / "flutter.apk"
    snapshot = b"\xf5\xf5\xdc\xd0" + bytes(range(16)) + b"\x00" * 32
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        archive.writestr("lib/arm64-v8a/libapp.so", snapshot)
        archive.writestr("lib/x86_64/libapp.so", snapshot)
    return path


def build_wasm() -> bytes:
    # magic + version 1 + one type section (id=1) of size 4.
    return b"\x00asm\x01\x00\x00\x00" + bytes([1, 4, 0, 0, 0, 0])


@pytest.fixture
def wasm_file(tmp_path: Path) -> Path:
    path = tmp_path / "module.wasm"
    path.write_bytes(build_wasm())
    return path


@pytest.fixture
def pcap_file(tmp_path: Path) -> Path:
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    return path


@pytest.fixture
def source_dir(tmp_path: Path) -> Path:
    root = tmp_path / "src"
    (root / "pkg").mkdir(parents=True)
    (root / "main.py").write_text("print('hi')\n")
    (root / "pkg" / "util.js").write_text("export const x = 1;\n")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "ignored.js").write_text("// ignored\n")
    return root


@pytest.fixture
def plist_file(tmp_path: Path) -> Path:
    import plistlib

    path = tmp_path / "Info.plist"
    path.write_bytes(
        plistlib.dumps({"CFBundleIdentifier": "com.example.app", "CFBundleVersion": "1.0"})
    )
    return path


def build_resource_blob() -> bytes:
    blob = bytearray()
    blob += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)  # root dir, 1 id entry
    blob += struct.pack("<II", 3, 0x80000000 | 16)  # type 3 (icon) -> subdir at 16
    blob += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)  # subdir, 1 entry
    blob += struct.pack("<II", 1, 40)  # one resource
    return bytes(blob)


def build_asar(files: dict[str, bytes]) -> bytes:
    header: dict[str, object] = {"files": {}}
    data = bytearray()
    for path, content in files.items():
        parts = path.split("/")
        node = header["files"]
        for part in parts[:-1]:
            assert isinstance(node, dict)
            node = node.setdefault(part, {"files": {}})["files"]  # type: ignore[assignment]
        assert isinstance(node, dict)
        node[parts[-1]] = {"size": len(content), "offset": str(len(data))}
        data += content
    json_bytes = json.dumps(header).encode()
    padded = json_bytes + b"\x00" * ((4 - len(json_bytes) % 4) % 4)
    header_payload = struct.pack("<I", len(json_bytes)) + padded
    return struct.pack("<II", 4, len(header_payload)) + header_payload + bytes(data)


@pytest.fixture
def har_file(tmp_path: Path) -> Path:
    import json

    path = tmp_path / "capture.har"
    path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://example.com/a"},
                            "response": {
                                "status": 200,
                                "content": {"mimeType": "text/html", "size": 10},
                            },
                        },
                        {
                            "request": {"method": "POST", "url": "https://api.example.com/b"},
                            "response": {
                                "status": 500,
                                "content": {"mimeType": "application/json", "size": 5},
                            },
                        },
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def saz_file(tmp_path: Path) -> Path:
    import zipfile

    path = tmp_path / "capture.saz"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "raw/1_c.txt", "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
        )
        archive.writestr("raw/1_s.txt", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
    return path


@pytest.fixture
def hap_file(tmp_path: Path) -> Path:
    import json
    import zipfile

    path = tmp_path / "entry.hap"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "module.json",
            json.dumps(
                {
                    "app": {
                        "bundleName": "com.example.app",
                        "versionName": "1.0.0",
                        "versionCode": 7,
                    },
                    "module": {"name": "entry"},
                }
            ),
        )
        archive.writestr("ets/entry.abc", b"abc-bytes")
        archive.writestr("libs/arm64-v8a/libentry.so", b"\x7fELF" + b"\x00" * 16)
    return path


@pytest.fixture
def keyed_archive_file(tmp_path: Path) -> Path:
    import plistlib

    path = tmp_path / "archive.plist"
    path.write_bytes(
        plistlib.dumps(
            {
                "$archiver": "NSKeyedArchiver",
                "$version": 100000,
                "$top": {"root": {"CF$UID": 0}},
                "$objects": [{"$classname": "NSString"}, {"$classname": "NSArray"}, "value"],
            },
            fmt=plistlib.FMT_BINARY,
        )
    )
    return path


@pytest.fixture
def js_dir(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "main.js").write_text(
        "const { ipcMain } = require('electron');\nrequire('./renderer');\n", encoding="utf-8"
    )
    (root / "renderer.js").write_text(
        "require('./util');\nconst { ipcRenderer } = require('electron');\n", encoding="utf-8"
    )
    (root / "util.js").write_text("module.exports = 1;\n", encoding="utf-8")
    return root


@pytest.fixture
def asar_file(tmp_path: Path) -> Path:
    path = tmp_path / "app.asar"
    path.write_bytes(
        build_asar(
            {
                "main.js": b"require('./lib/util');\nconst {ipcMain}=require('electron');\n",
                "lib/util.js": b"module.exports = 2;\n",
            }
        )
    )
    return path


@pytest.fixture
def pe_resources_file(tmp_path: Path) -> Path:
    path = tmp_path / "resources.exe"
    path.write_bytes(build_pe(resource_blob=build_resource_blob()))
    return path


@pytest.fixture
def asset_catalog_file(tmp_path: Path) -> Path:
    path = tmp_path / "Assets.car"
    path.write_bytes(b"CORE\x00\x00\x00\x01" + b"RenditionName\x00\x00" + b"AppIcon\x00")
    return path


@pytest.fixture
def plain_file(tmp_path: Path) -> Path:
    path = tmp_path / "notes.txt"
    path.write_bytes(b"just some text\n")
    return path


@pytest.fixture
def electron_file(tmp_path: Path) -> Path:
    sentinel = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
    wire = bytes([0x31, 0x31, 0x30, 0x30, 0x31, 0x30, 0x30, 0x30])  # enabled/disabled pattern
    path = tmp_path / "electron.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 56 + sentinel + bytes([1, len(wire)]) + wire)
    return path


def _dns_ethernet_frame(query: str = "example.com") -> bytes:
    labels = query.split(".")
    qname = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\x00"
    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 40000, 53, 8 + len(dns), 0) + dns
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        0,
        0,
        64,
        17,
        0,
        bytes([192, 168, 0, 1]),
        bytes([8, 8, 8, 8]),
    )
    ethernet = bytes(6) + bytes([1, 2, 3, 4, 5, 6]) + struct.pack(">H", 0x0800)
    return ethernet + ip + udp


def build_pcap_with_dns(query: str = "example.com") -> bytes:
    """Build a classic little-endian pcap with one Ethernet/IPv4/UDP DNS query."""

    frame = _dns_ethernet_frame(query)
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1_700_000_000, 0, len(frame), len(frame)) + frame
    return global_header + record


def build_pcapng_with_dns(query: str = "example.com") -> bytes:
    """Build a minimal pcapng with one Ethernet/IPv4/UDP DNS packet."""

    def block(block_type: int, body: bytes) -> bytes:
        total = 12 + len(body)
        return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)

    section = block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    frame = _dns_ethernet_frame(query)
    padded = frame + b"\x00" * ((-len(frame)) % 4)
    enhanced = block(
        6,
        struct.pack("<IIIII", 0, 0, 1_700_000_000, len(frame), len(frame)) + padded,
    )
    return section + interface + enhanced


@pytest.fixture
def pcap_dns_file(tmp_path: Path) -> Path:
    path = tmp_path / "dns.pcap"
    path.write_bytes(build_pcap_with_dns())
    return path


@pytest.fixture
def pcapng_dns_file(tmp_path: Path) -> Path:
    path = tmp_path / "dns.pcapng"
    path.write_bytes(build_pcapng_with_dns())
    return path


@pytest.fixture
def firmware_file(tmp_path: Path) -> Path:
    blob = bytearray(b"\x00" * 0x2000)
    blob[0:4] = b"\x27\x05\x19\x56"
    blob[0x1000:0x1004] = b"hsqs"
    path = tmp_path / "firmware.bin"
    path.write_bytes(bytes(blob))
    return path


@pytest.fixture
def pe_clr_file_b(tmp_path: Path) -> Path:
    path = tmp_path / "managed_b.exe"
    path.write_bytes(
        build_pe(
            clr=True,
            metadata_blob=metadata_blob(
                type_name="OtherType", namespace="Other.Namespace", method_name="OtherMethod"
            ),
        )
    )
    return path


@pytest.fixture
def interface_builder_file(tmp_path: Path) -> Path:
    import plistlib

    path = tmp_path / "Main.nib"
    path.write_bytes(
        plistlib.dumps(
            {
                "$archiver": "NSKeyedArchiver",
                "$version": 100000,
                "$objects": [
                    {"$classname": "NSView", "$classes": ["NSView"]},
                    {"$classname": "NSButton"},
                ],
            },
            fmt=plistlib.FMT_BINARY,
        )
    )
    return path


@pytest.fixture
def big_plist_file(tmp_path: Path) -> Path:
    import plistlib

    path = tmp_path / "big.plist"
    path.write_bytes(plistlib.dumps({"blob": "x" * 6000}))
    return path


def build_uart_vcd(data: bytes, *, baud: int = 9600, timescale_seconds: float = 1e-6) -> str:
    bit = (1.0 / baud) / timescale_seconds
    levels: list[tuple[int, str]] = [(0, "1")]

    def emit(tick: float, level: str) -> None:
        if levels[-1][1] != level:
            levels.append((round(tick), level))

    clock = 0.0
    for byte in data:
        emit(clock, "0")
        for index in range(8):
            emit(clock + (1 + index) * bit, "1" if (byte >> index) & 1 else "0")
        emit(clock + 9 * bit, "1")
        clock += 10 * bit
    lines = [f"#{tick}\n{level}!" for tick, level in levels]
    return (
        "$timescale 1 us $end\n"
        "$scope module logic $end\n"
        "$var wire 1 ! tx $end\n"
        "$upscope $end\n"
        "$enddefinitions $end\n" + "\n".join(lines) + "\n"
    )


@pytest.fixture
def vcd_file(tmp_path: Path) -> Path:
    path = tmp_path / "uart.vcd"
    path.write_text(build_uart_vcd(b"OK"), encoding="utf-8")
    return path


@pytest.fixture
def crash_dump_file(tmp_path: Path) -> Path:
    path = tmp_path / "crash.txt"
    path.write_text(
        "Program received signal SIGSEGV, Segmentation fault.\n"
        "0x0000555555555150 in main ()\n"
        "rax            0x0                 0\n"
        "rip            0x0000555555555150  0x555555555150 <main+16>\n"
        "#0  0x0000555555555150 in main ()\n"
        "#1  0x00007ffff7e08d90 in __libc_start_main ()\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def har_file_b(tmp_path: Path) -> Path:
    import json

    path = tmp_path / "capture_b.har"
    path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://example.com/a"},
                            "response": {
                                "status": 200,
                                "content": {"mimeType": "text/html", "size": 10},
                            },
                        },
                        {
                            "request": {"method": "DELETE", "url": "https://example.com/c"},
                            "response": {
                                "status": 204,
                                "content": {"mimeType": "text/plain", "size": 0},
                            },
                        },
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    return path
