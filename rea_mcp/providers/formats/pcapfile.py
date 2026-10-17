"""Pure-Python classic-pcap / pcapng parser (no external tools)."""

from __future__ import annotations

import mmap
import struct
from typing import Any

_CLASSIC_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def parse_capture(data: bytes | mmap.mmap) -> dict[str, Any] | None:
    """Return a transport-summary dict, or ``None`` when the data is not a capture."""

    read = _read_capture(data)
    if read is None:
        return None
    linktypes, packets = read
    return _summarise(packets, linktypes)


def parse_packets(data: bytes | mmap.mmap, *, limit: int = 500) -> dict[str, Any] | None:
    """Return per-packet field records (bounded) plus the summary."""

    read = _read_capture(data)
    if read is None:
        return None
    linktypes, packets = read
    records: list[dict[str, Any]] = []
    for index, (timestamp, frame) in enumerate(packets[:limit]):
        record: dict[str, Any] = {
            "index": index,
            "timestamp": timestamp,
            "captured_length": len(frame),
        }
        parsed = _parse_frame(frame, linktypes[0] if linktypes else None)
        if parsed is not None:
            record.update(parsed)
        records.append(record)
    summary = _summarise(packets, linktypes)
    summary["packets"] = records
    summary["returned_packet_count"] = len(records)
    summary["truncated"] = len(packets) > len(records)
    return summary


def _read_capture(
    data: bytes | mmap.mmap,
) -> tuple[list[int], list[tuple[float, bytes]]] | None:
    if len(data) >= 24 and data[:4] in _CLASSIC_MAGICS:
        return _read_classic(data)
    if len(data) >= 12 and data[:4] == _PCAPNG_MAGIC:
        return _read_pcapng(data)
    return None


def _read_classic(
    data: bytes | mmap.mmap,
) -> tuple[list[int], list[tuple[float, bytes]]]:
    endian, resolution = _CLASSIC_MAGICS[data[:4]]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    packets: list[tuple[float, bytes]] = []
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + incl_len > len(data):
            break
        packets.append((ts_sec + ts_frac / resolution, data[offset : offset + incl_len]))
        offset += incl_len
    return [linktype], packets


def _read_pcapng(
    data: bytes | mmap.mmap,
) -> tuple[list[int], list[tuple[float, bytes]]]:
    linktypes: list[int] = []
    packets: list[tuple[float, bytes]] = []
    offset = 0
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack_from("<II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            break
        body = data[offset + 8 : offset + block_len - 4]
        if block_type == 1 and len(body) >= 8:  # Interface Description Block
            linktypes.append(struct.unpack_from("<H", body, 0)[0])
        elif block_type == 6 and len(body) >= 20:  # Enhanced Packet Block
            _interface_id, ts_high, ts_low, cap_len = struct.unpack_from("<IIII", body, 0)
            packets.append((((ts_high << 32) | ts_low) / 1_000_000, body[20 : 20 + cap_len]))
        offset += block_len
    return linktypes, packets


def _summarise(packets: list[tuple[float, bytes]], linktypes: list[int]) -> dict[str, Any]:
    protocols: set[str] = set()
    endpoints: set[str] = set()
    dns_queries: list[str] = []
    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()
    for _ts, frame in packets:
        parsed = _parse_frame(frame, linktypes[0] if linktypes else None)
        if parsed is None:
            continue
        protocols.update(parsed["protocols"])
        if parsed.get("endpoint"):
            endpoints.add(parsed["endpoint"])
        tcp_ports.update(parsed.get("tcp_ports", ()))
        udp_ports.update(parsed.get("udp_ports", ()))
        if parsed.get("dns_query"):
            dns_queries.append(parsed["dns_query"])
    timestamps = [ts for ts, _ in packets]
    return {
        "linktypes": linktypes,
        "packet_count": len(packets),
        "protocols": sorted(protocols),
        "endpoints": sorted(endpoints),
        "tcp_ports": sorted(tcp_ports),
        "udp_ports": sorted(udp_ports),
        "dns_queries": sorted(set(dns_queries)),
        "first_timestamp": min(timestamps) if timestamps else None,
        "last_timestamp": max(timestamps) if timestamps else None,
    }


def _parse_frame(frame: bytes, linktype: int | None) -> dict[str, Any] | None:
    if (linktype in (1, 101) and len(frame) >= 14) or (
        linktype is None and len(frame) >= 14
    ):  # Ethernet / LINKTYPE_RAW-ish
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        payload = frame[14:]
    else:
        return None
    if ethertype == 0x0800:
        return _parse_ipv4(payload)
    if ethertype == 0x86DD:
        return _parse_ipv6(payload)
    if ethertype == 0x0806:
        return {"protocols": ["ARP"]}
    return None


def _parse_ipv4(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 20:
        return None
    ihl = (payload[0] & 0x0F) * 4
    proto = payload[9]
    src = ".".join(str(b) for b in payload[12:16])
    dst = ".".join(str(b) for b in payload[16:20])
    return _transport(proto, src, dst, payload[ihl:])


def _parse_ipv6(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 40:
        return None
    proto = payload[6]
    src = ":".join(f"{payload[i + 1]:02x}{payload[i + 2]:02x}" for i in range(0, 16, 2))
    dst = ":".join(f"{payload[i + 17]:02x}{payload[i + 18]:02x}" for i in range(0, 16, 2))
    return _transport(proto, src, dst, payload[40:])


def _transport(proto: int, src: str, dst: str, transport: bytes) -> dict[str, Any]:
    base: dict[str, Any] = {"endpoint": f"{src}->{dst}", "src": src, "dst": dst}
    if proto == 6 and len(transport) >= 4:  # TCP
        sport, dport = struct.unpack_from(">HH", transport, 0)
        base["protocols"] = ["TCP"]
        base["tcp_ports"] = (sport, dport)
        base["sport"] = sport
        base["dport"] = dport
    elif proto == 17 and len(transport) >= 8:  # UDP
        sport, dport = struct.unpack_from(">HH", transport, 0)
        base["protocols"] = ["UDP"]
        base["udp_ports"] = (sport, dport)
        base["sport"] = sport
        base["dport"] = dport
        if 53 in (sport, dport):
            base["protocols"] = ["UDP", "DNS"]
            query = _dns_query(transport[8:])
            if query:
                base["dns_query"] = query
    else:
        base["protocols"] = [f"IP{proto}"]
    return base


def _dns_query(payload: bytes) -> str | None:
    if len(payload) < 12:
        return None
    labels: list[str] = []
    offset = 12
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            break
        if length & 0xC0:
            break
        offset += 1
        if offset + length > len(payload):
            return None
        labels.append(payload[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels) if labels else None


__all__ = ["parse_capture", "parse_packets"]
