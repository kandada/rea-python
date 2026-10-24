"""Static APK v1/v2/v3/v3.1 signature inventory without signature verification.

The reader frames the APK Signing Block, decodes signer/digest/certificate/SDK
and proof-of-rotation attributes, extracts v1 PKCS#7 certificates, and reads the
source-stamp certificate. Cryptographic signature validity and trust are never
claimed; content digests can be compared with the current file.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path
from typing import Any

from ..domain.analysis_error import AnalysisError, AnalysisInputError
from ..domain.analysis_profile import ProviderIdentity
from ..domain.binary_target import BinaryTarget
from ..domain.result import Result, err, ok
from .base import AnalysisExecution, AnalysisProvider, CapabilityDescriptor, CapabilityEffects
from .registry import TargetSupport

_PROVIDER = ProviderIdentity(id="apk-signature", name="REA-Python APK signatures", version="1")
_MAGIC = b"APK Sig Block 42"
_V2 = 0x7109871A
_V3 = 0xF05368C0
_V31 = 0x1B93AD61
_STAMP_V1 = 0x2B09189E
_STAMP_V2 = 0x6DFF800D
_ROTATION = 0x3BA06F8C
_MAX_SIGNERS = 32
_MAX_LINEAGE = 32

_ALGORITHMS = {
    0x0101: ("RSASSA-PSS", "sha256"),
    0x0102: ("RSASSA-PSS", "sha512"),
    0x0103: ("RSASSA-PKCS1-v1_5", "sha256"),
    0x0104: ("RSASSA-PKCS1-v1_5", "sha512"),
    0x0201: ("ECDSA", "sha256"),
    0x0202: ("ECDSA", "sha512"),
    0x0301: ("DSA", "sha256"),
    0x0421: ("RSASSA-PKCS1-v1_5-verity", "sha256"),
    0x0423: ("ECDSA-verity", "sha256"),
    0x0425: ("DSA-verity", "sha256"),
}


class ApkSignatureProvider(AnalysisProvider):
    def identity(self) -> ProviderIdentity:
        return _PROVIDER

    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return (
            CapabilityDescriptor(
                operation="inspect_apk_signature",
                provider=_PROVIDER,
                effects=CapabilityEffects(),
                limitations=(
                    "Declared signatures and certificate facts are reported; cryptographic validity and trust are not verified.",
                ),
            ),
        )

    def supports(self, target: BinaryTarget) -> TargetSupport:
        if target.format == "apk" or target.path.lower().endswith(".apk"):
            return TargetSupport("supported")
        return TargetSupport("unsupported", reason="not an APK", code="target_format_unsupported")

    def analyze(
        self,
        operation: str,
        target: BinaryTarget,
        parameters: dict[str, Any],
        profile: Any,
    ) -> Result[AnalysisExecution, AnalysisError]:
        del parameters, profile
        if operation != "inspect_apk_signature":
            return err(
                AnalysisInputError(
                    operation=operation, message=f"unsupported operation {operation}"
                )
            )
        try:
            data = Path(target.path).read_bytes()
        except OSError as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        try:
            result = _inspect(data)
        except (ValueError, struct.error, zipfile.BadZipFile) as cause:
            return err(AnalysisInputError(operation=operation, message=str(cause)))
        return ok(AnalysisExecution(result=result, provider=_PROVIDER))


def _inspect(data: bytes) -> dict[str, Any]:
    v1 = _v1(data)
    schemes: list[dict[str, Any]] = []
    block = _signing_block(data)
    if block is not None:
        for scheme, identifier in (("v2", _V2), ("v3", _V3), ("v3.1", _V31)):
            value = block.get(identifier)
            if value is None:
                continue
            signers, uninterpreted = _signers(value, scheme)
            schemes.append(
                {
                    "scheme": scheme,
                    "signers": signers,
                    "signer_count": len(signers),
                    "uninterpreted_bytes": uninterpreted,
                }
            )
    block_start = _block_start(data)
    if block_start is not None:
        expected = {}
        for algorithm in ("sha256", "sha512"):
            digest = _content_digest(data, block_start, algorithm)
            if digest is not None:
                expected[algorithm] = digest
        for scheme_entry in schemes:
            scheme_signers = scheme_entry["signers"]
            assert isinstance(scheme_signers, list)
            for signer in scheme_signers:
                assert isinstance(signer, dict)
                signer["digests_matches_apk"] = [
                    {
                        **digest,
                        "matches_apk": (
                            expected.get(digest["algorithm"])
                            == bytes.fromhex(digest["digest_sha256"])
                            if digest["algorithm"] in ("sha256", "sha512")
                            else None
                        ),
                    }
                    for digest in signer["digests"]
                ]
                certs = signer.pop("_certificate_ders", [])
                raw_signatures = signer.pop("_signatures_raw", [])
                signed_data = signer.pop("_signed_data", None)
                if certs and signed_data is not None:
                    signer["signature_valid"] = any(
                        _verify_signature(certs[0], algorithm, signed_data, signature) is True
                        for algorithm, signature in raw_signatures
                    )
                else:
                    signer["signature_valid"] = None
    stamp = _source_stamp(block)
    fingerprints = {
        signer["certificate"]["sha256_fingerprint"]
        for scheme in schemes
        for signer in scheme["signers"]
        if signer.get("certificate")
    }
    fingerprints.update(item["sha256"] for item in v1["certificates"] if item.get("sha256"))
    posture = {
        "signing_certificate_count": len(fingerprints),
        "block_scheme_count": len(schemes),
        "v1_present": v1["present"],
        "source_stamp_present": stamp["present"],
        "self_consistent": len(fingerprints) <= 1,
    }
    return {
        "has_signatures": bool(v1.get("present") or schemes or stamp["present"]),
        "v1": v1,
        "schemes": schemes,
        "scheme_count": len(schemes),
        "source_stamp": stamp,
        "posture": posture,
        "runtime_execution": "not-performed",
        "limitations": (
            "Content digests and certificate facts are reported, not cryptographically verified.",
        ),
    }


def _v1(data: bytes) -> dict[str, Any]:
    import io
    import zlib

    entries: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            for name in names:
                if name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC")):
                    raw = archive.read(name)
                    certificates = _pkcs7_certificates(raw, zlib)
                    entries.append(
                        {
                            "path": name,
                            "size": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "certificates": certificates,
                            "decode_error": None
                            if certificates
                            else "PKCS#7 certificates were not readable",
                        }
                    )
            manifest = "META-INF/MANIFEST.MF" in names
    except zipfile.BadZipFile:
        return {"present": False, "has_manifest": False, "certificates": []}
    return {
        "present": bool(entries),
        "has_manifest": manifest,
        "certificates": entries,
        "certificate_count": len(entries),
    }


def _pkcs7_certificates(raw: bytes, zlib: Any) -> list[dict[str, Any]]:
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7

        certs = pkcs7.load_der_pkcs7_certificates(raw)
    except Exception:
        try:
            certs = pkcs7.load_der_pkcs7_certificates(_inflate(raw, zlib))
        except Exception:
            return []
    return [
        _certificate_facts(
            cert.public_bytes(
                __import__(
                    "cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]
                ).Encoding.DER
            )
        )
        for cert in certs
    ]


def _inflate(raw: bytes, zlib: Any) -> bytes:
    try:
        return bytes(zlib.decompress(raw, -15))
    except Exception:
        return bytes(zlib.decompress(raw))


def _certificate_chain(ders: list[bytes]) -> dict[str, Any]:
    try:
        from datetime import datetime, timezone

        from cryptography import x509

        certs = [x509.load_der_x509_certificate(der) for der in ders]
        by_subject = {cert.subject.public_bytes(): cert for cert in certs}
        chain: list[dict[str, Any]] = []
        current = certs[0] if certs else None
        seen: set[bytes] = set()
        while current is not None and len(chain) < 16:
            subject = current.subject.public_bytes()
            if subject in seen:
                break
            seen.add(subject)
            now = datetime.now(timezone.utc)
            chain.append(
                {
                    **_certificate_facts(
                        current.public_bytes(
                            __import__(
                                "cryptography.hazmat.primitives.serialization",
                                fromlist=["Encoding"],
                            ).Encoding.DER
                        )
                    ),
                    "valid_now": current.not_valid_before_utc <= now <= current.not_valid_after_utc,
                    "self_signed": current.issuer == current.subject,
                }
            )
            if current.issuer == current.subject:
                break
            current = by_subject.get(current.issuer.public_bytes())
        return {
            "certificates": chain,
            "chain_complete": bool(chain and chain[-1]["self_signed"]),
            "self_signed": bool(len(chain) == 1 and chain[0]["self_signed"]),
            "all_valid_now": all(item["valid_now"] for item in chain),
            "trust_verified": False,
            "revocation_checked": False,
        }
    except Exception as cause:
        return {
            "certificates": [],
            "chain_complete": False,
            "self_signed": None,
            "all_valid_now": None,
            "trust_verified": False,
            "revocation_checked": False,
            "decode_error": str(cause),
        }


def _certificate_facts(der: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "der_length": len(der),
        "subject": None,
        "issuer": None,
        "serial_number": None,
        "not_before": None,
        "not_after": None,
        "public_key_algorithm": None,
    }
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        result.update(
            {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": f"{cert.serial_number:x}",
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "public_key_algorithm": getattr(
                    getattr(cert.public_key(), "algorithm", None), "name", None
                ),
            }
        )
    except Exception:
        pass
    return result


def _block_start(data: bytes) -> int | None:
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0:
        return None
    central = int(struct.unpack_from("<I", data, eocd + 16)[0])
    if central < 24 or data[central - 16 : central] != _MAGIC:
        return None
    size = int(struct.unpack_from("<Q", data, central - 24)[0])
    return central - (size + 8)


def _signing_block(data: bytes) -> dict[int, bytes] | None:
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0 or eocd + 22 > len(data):
        return None
    central = int(struct.unpack_from("<I", data, eocd + 16)[0])
    if central < 24 or data[central - 16 : central] != _MAGIC:
        return None
    size = struct.unpack_from("<Q", data, central - 24)[0]
    start = central - (size + 8)
    if start < 0:
        raise ValueError("APK signing block extends before the file")
    cursor = start + 8
    end = central - 24
    pairs: dict[int, bytes] = {}
    while cursor + 12 <= end:
        length = struct.unpack_from("<Q", data, cursor)[0]
        cursor += 8
        identifier = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        if length < 4 or cursor + length - 4 > end:
            raise ValueError("truncated APK signing block pair")
        pairs[identifier] = data[cursor : cursor + length - 4]
        cursor += length - 4
    return pairs


def _content_digest(data: bytes, block_start: int, algorithm: str) -> bytes | None:
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0 or eocd + 22 > len(data):
        return None
    central = int(struct.unpack_from("<I", data, eocd + 16)[0])
    if central < block_start:
        return None
    eocd_bytes = bytearray(data[eocd:])
    struct.pack_into("<I", eocd_bytes, 16, block_start)
    sections = [
        data[:block_start],
        data[central:eocd],
        bytes(eocd_bytes),
    ]
    chunks = []
    for section in sections:
        for offset in range(0, len(section), 1024 * 1024):
            chunk = section[offset : offset + 1024 * 1024]
            hasher = hashlib.new(algorithm)
            hasher.update(b"\xa5")
            hasher.update(struct.pack("<I", len(chunk)))
            hasher.update(chunk)
            chunks.append(hasher.digest())
    top = hashlib.new(algorithm)
    top.update(b"\x5a")
    top.update(struct.pack("<I", len(chunks)))
    for chunk in chunks:
        top.update(chunk)
    return bytes(top.digest())


def _verify_signature(
    certificate_der: bytes, algorithm_id: int, signed_data: bytes, signature: bytes
) -> bool | None:
    if algorithm_id not in _ALGORITHMS:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

        cert = x509.load_der_x509_certificate(certificate_der)
        public_key = cert.public_key()
        hash_algorithm = (
            hashes.SHA512() if algorithm_id in (0x0102, 0x0104, 0x0202) else hashes.SHA256()
        )
        if isinstance(public_key, rsa.RSAPublicKey):
            if algorithm_id in (0x0101, 0x0102):
                public_key.verify(
                    signature,
                    signed_data,
                    padding.PSS(
                        mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_algorithm,
                )
            else:
                public_key.verify(signature, signed_data, padding.PKCS1v15(), hash_algorithm)
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_data, ec.ECDSA(hash_algorithm))
            return True
        if isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, signed_data, hash_algorithm)
            return True
    except Exception:
        return False
    return None


def _signers(value: bytes, scheme: str) -> tuple[list[dict[str, Any]], int]:
    if len(value) < 4:
        return [], len(value)
    signers_len = struct.unpack_from("<I", value, 0)[0]
    cursor = 4
    end = min(len(value), 4 + signers_len)
    signers: list[dict[str, Any]] = []
    while cursor + 4 <= end and len(signers) < _MAX_SIGNERS:
        signer_len = struct.unpack_from("<I", value, cursor)[0]
        cursor += 4
        signer_end = min(end, cursor + signer_len)
        try:
            signed = _chunk(value, cursor)
            if signed is None:
                break
            signed_data, cursor = signed
            decoded = _signed_data(signed_data, scheme)
            if decoded is None:
                break
            if scheme != "v2":
                min_sdk, cursor = _u32(value, cursor)
                max_sdk, cursor = _u32(value, cursor)
                if min_sdk is None or max_sdk is None:
                    break
                decoded["min_sdk"] = min_sdk
                decoded["max_sdk"] = max_sdk
            signatures, cursor = _algorithm_records(value, cursor)
            public_part = _chunk(value, cursor)
            if public_part is None:
                break
            public_key, cursor = public_part
            decoded["_signed_data"] = signed_data
            decoded["_certificate_ders"] = decoded.get("certificates") or []
            decoded["_signatures_raw"] = signatures
            decoded["signatures"] = [
                {
                    "algorithm_id": algorithm,
                    "algorithm": _algorithm_name(algorithm),
                    "signature_bytes": len(signature),
                }
                for algorithm, signature in signatures
            ]
            decoded["public_key_bytes"] = len(public_key)
            decoded["certificate"] = (
                _certificate_facts(decoded["certificates"][0]) if decoded["certificates"] else None
            )
            decoded["rotation"] = _rotation(decoded.get("attributes") or [])
            signers.append(decoded)
        except (ValueError, struct.error):
            break
        cursor = signer_end
    return signers, max(0, len(value) - cursor)


def _signed_data(value: bytes, scheme: str) -> dict[str, Any] | None:
    cursor = 0
    digests_part = _chunk(value, cursor)
    if digests_part is None:
        return None
    digests_chunk, cursor = digests_part
    digests = _algorithm_records(digests_chunk, 0)[0]
    certificates_part = _chunk(value, cursor)
    if certificates_part is None:
        return None
    certificates_chunk, cursor = certificates_part
    certificates = []
    c = 0
    while c + 4 <= len(certificates_chunk):
        cert, c = _chunk(certificates_chunk, c) or (None, c)
        if cert is None:
            break
        certificates.append(cert)
    min_sdk = max_sdk = None
    if scheme != "v2":
        min_sdk, cursor = _u32(value, cursor)
        max_sdk, cursor = _u32(value, cursor)
    attributes_part = _chunk(value, cursor)
    attributes_chunk = attributes_part[0] if attributes_part is not None else None
    cursor = attributes_part[1] if attributes_part is not None else cursor
    attributes = []
    if attributes_chunk is not None:
        a = 0
        while a + 4 <= len(attributes_chunk):
            identifier = struct.unpack_from("<I", attributes_chunk, a)[0]
            a += 4
            chunk, a = _chunk(attributes_chunk, a) or (None, a)
            if chunk is None:
                break
            attributes.append({"id": identifier, "value": chunk})
    return {
        "digests": [
            {
                "algorithm_id": algorithm,
                "algorithm": _algorithm_name(algorithm),
                "digest_sha256": hashlib.sha256(digest).hexdigest(),
                "digest_bytes": len(digest),
            }
            for algorithm, digest in digests
        ],
        "certificates": certificates,
        "min_sdk": min_sdk,
        "max_sdk": max_sdk,
        "attributes": attributes,
    }


def _rotation(attributes: list[dict[str, Any]]) -> dict[str, Any]:
    attribute = next((item for item in attributes if item["id"] == _ROTATION), None)
    if attribute is None:
        return {"present": False, "lineage": [], "decode_error": None}
    value = attribute["value"]
    if len(value) < 4:
        return {"present": True, "lineage": [], "decode_error": "lineage version missing"}
    version = struct.unpack_from("<I", value, 0)[0]
    if version != 1:
        return {
            "present": True,
            "lineage": [],
            "decode_error": f"unsupported lineage version {version}",
        }
    cursor = 4
    lineage: list[dict[str, Any]] = []
    while cursor + 4 <= len(value) and len(lineage) < _MAX_LINEAGE:
        node_part = _chunk(value, cursor)
        if node_part is None:
            break
        node, cursor = node_part
        n = 0
        signed_part = _chunk(node, n)
        if signed_part is None:
            break
        signed, n = signed_part
        if n + 4 > len(node):
            break
        flags = struct.unpack_from("<I", node, n)[0]
        s = 0
        cert_part = _chunk(signed, s)
        if cert_part is None:
            break
        cert, s = cert_part
        lineage.append(
            {
                "certificate": _certificate_facts(cert),
                "flags": flags,
                "capabilities": {
                    "installed_data": bool(flags & 1),
                    "shared_uid": bool(flags & 2),
                    "permission": bool(flags & 4),
                    "rollback": bool(flags & 8),
                    "auth": bool(flags & 16),
                },
            }
        )
    return {"present": True, "lineage": lineage, "decode_error": None}


def _source_stamp(block: dict[int, bytes] | None) -> dict[str, Any]:
    if block is None:
        return {"present": False, "certificate": None, "decode_error": None}
    value = block.get(_STAMP_V2) or block.get(_STAMP_V1)
    if value is None:
        return {"present": False, "certificate": None, "decode_error": None}
    chunk_part = _chunk(value, 0) if len(value) >= 4 else None
    if chunk_part is None:
        return {"present": True, "certificate": None, "decode_error": "source stamp data truncated"}
    chunk = chunk_part[0]
    cert_part = _chunk(chunk, 0) if len(chunk) >= 4 else None
    if cert_part is None:
        return {
            "present": True,
            "certificate": None,
            "decode_error": "source stamp certificate missing",
        }
    return {"present": True, "certificate": _certificate_facts(cert_part[0]), "decode_error": None}


def _algorithm_records(value: bytes, cursor: int) -> tuple[list[tuple[int, bytes]], int]:
    chunk, cursor = _chunk(value, cursor) or (None, cursor)
    if chunk is None:
        return [], cursor
    records = []
    c = 0
    while c + 4 <= len(chunk):
        algorithm = struct.unpack_from("<I", chunk, c)[0]
        c += 4
        data, c = _chunk(chunk, c) or (None, c)
        if data is None:
            break
        records.append((algorithm, data))
    return records, cursor


def _chunk(value: bytes, cursor: int) -> tuple[bytes, int] | None:
    if cursor + 4 > len(value):
        return None
    length = struct.unpack_from("<I", value, cursor)[0]
    cursor += 4
    if length > len(value) - cursor:
        return None
    return value[cursor : cursor + length], cursor + length


def _u32(value: bytes, cursor: int) -> tuple[int, int]:
    if cursor + 4 > len(value):
        raise ValueError("truncated uint32")
    return struct.unpack_from("<I", value, cursor)[0], cursor + 4


def _algorithm_name(identifier: int) -> str:
    return _ALGORITHMS.get(identifier, ("unknown", "unknown"))[0]


__all__ = ["ApkSignatureProvider"]
