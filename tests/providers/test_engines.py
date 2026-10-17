"""Conditional engine tests.

Every adapter's unavailable path is always asserted. The real-operation tests
run only when the caller has supplied the corresponding engine/environment, and
are otherwise a *named skip* keyed on that availability.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from rea_mcp.composition.factories import build_providers
from rea_mcp.domain.binary_target import parse_binary_target
from rea_mcp.providers.base import AnalysisProvider
from rea_mcp.providers.engines import AdbProvider, ApktoolProvider, KunaProvider, SignalProvider
from rea_mcp.providers.hopper import HopperProvider
from rea_mcp.providers.optional_engines import (
    BrowserProvider,
    FridaProvider,
    GhidraProvider,
    IdaProvider,
    JebProvider,
    RecordedCrashProvider,
)

ENGINES: list[AnalysisProvider] = [
    ApktoolProvider(),
    AdbProvider(),
    SignalProvider(),
    KunaProvider(),
    GhidraProvider(),
    HopperProvider(),
    IdaProvider(),
    JebProvider(),
    FridaProvider(),
    BrowserProvider(),
    RecordedCrashProvider(),
]


def _target(path: Path) -> object:
    result = parse_binary_target(path)
    assert result.ok
    return result.value


def _available(provider: AnalysisProvider) -> bool:
    return all(cap.available for cap in provider.capabilities())


def test_engines_are_registered() -> None:
    registry_ids = {provider.identity().id for provider in build_providers()}
    engine_ids = {provider.identity().id for provider in ENGINES}
    assert engine_ids <= registry_ids


@pytest.mark.parametrize("provider", ENGINES, ids=lambda p: p.identity().id)
def test_capabilities_are_wellformed(provider: AnalysisProvider) -> None:
    capabilities = provider.capabilities()
    assert capabilities
    for capability in capabilities:
        assert capability.operation
        if not capability.available:
            assert capability.reason  # unavailable providers must explain why


@pytest.mark.parametrize("provider", ENGINES, ids=lambda p: p.identity().id)
def test_unavailable_reports_capability_error(provider: AnalysisProvider, elf_file: Path) -> None:
    if _available(provider):
        pytest.skip("engine is available; covered by the real-operation test")
    capability = provider.capabilities()[0]
    result = provider.analyze(capability.operation, _target(elf_file), {}, None)
    assert not result.ok
    assert result.error.tag == "AnalysisCapabilityUnavailableError"


@pytest.mark.real_engine
@pytest.mark.skipif(not _available(ApktoolProvider()), reason="requires apktool + JRE")
def test_apktool_real(apk_file: Path) -> None:
    result = ApktoolProvider().analyze("decode_android_resources", _target(apk_file), {}, None)
    assert result.ok
    assert result.value.result["file_count"] >= 1


@pytest.mark.real_engine
@pytest.mark.skipif(
    not os.environ.get("REA_ADB_DEVICE"), reason="requires REA_ADB_DEVICE + adb device"
)
def test_adb_real_devices(elf_file: Path) -> None:
    result = AdbProvider().analyze("list_adb_devices", _target(elf_file), {}, None)
    assert result.ok
    assert result.value.result["lines"]


@pytest.mark.real_engine
@pytest.mark.skipif(not os.environ.get("REA_SIGNAL_FIXTURE"), reason="requires REA_SIGNAL_FIXTURE")
def test_signal_real(elf_file: Path) -> None:
    fixture = os.environ["REA_SIGNAL_FIXTURE"]
    result = SignalProvider().analyze(
        "decode_signal_recording",
        _target(Path(fixture)),
        {"decoder": os.environ.get("REA_SIGNAL_DECODER", "spi")},
        None,
    )
    assert result.ok


@pytest.mark.real_engine
@pytest.mark.skipif(not _available(KunaProvider()), reason="requires REA_KUNA_COMMAND")
def test_kuna_real(elf_file: Path) -> None:
    result = KunaProvider().analyze("kuna_decompile", _target(elf_file), {}, None)
    assert result.ok


@pytest.mark.real_engine
@pytest.mark.skipif(not _available(GhidraProvider()), reason="requires pyhidra + Ghidra + JDK")
def test_ghidra_real(elf_file: Path) -> None:
    result = GhidraProvider().analyze("ghidra_analyze", _target(elf_file), {}, None)
    assert result.ok
    assert "function_count" in result.value.result


@pytest.mark.real_engine
@pytest.mark.skipif(not _available(FridaProvider()), reason="requires the optional frida package")
def test_frida_real_devices(elf_file: Path) -> None:
    result = FridaProvider().analyze("list_frida_devices", _target(elf_file), {}, None)
    assert result.ok
    assert isinstance(result.value.result["devices"], list)


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (_available(BrowserProvider()) and os.environ.get("REA_BROWSER_TEST_URL")),
    reason="requires REA_BROWSER_EXECUTABLE + playwright + REA_BROWSER_TEST_URL",
)
def test_browser_real(elf_file: Path) -> None:
    url = os.environ["REA_BROWSER_TEST_URL"]
    result = BrowserProvider().analyze("observe_web_page", _target(elf_file), {"url": url}, None)
    assert result.ok
    assert result.value.result["url"]


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (os.environ.get("REA_PWNTOOLS_PYTHON") and os.environ.get("REA_CRASH_FIXTURE")),
    reason="requires REA_PWNTOOLS_PYTHON + REA_CRASH_FIXTURE",
)
def test_recorded_crash_real() -> None:
    core = Path(os.environ["REA_CRASH_FIXTURE"])
    executable = os.environ.get("REA_CRASH_EXECUTABLE", str(core))
    result = RecordedCrashProvider().analyze(
        "inspect_recorded_crash", _target(core), {"executable": executable}, None
    )
    assert result.ok
