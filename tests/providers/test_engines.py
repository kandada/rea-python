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
from rea_mcp.providers.android_deep import AndroidDeepProvider
from rea_mcp.providers.base import AnalysisProvider
from rea_mcp.providers.debug_sessions import DebugSessionProvider
from rea_mcp.providers.engines import (
    AdbProvider,
    ApktoolProvider,
    JadxProvider,
    KunaProvider,
    SignalProvider,
)
from rea_mcp.providers.hopper import HopperProvider
from rea_mcp.providers.optional_engines import (
    BrowserProvider,
    FridaProvider,
    GhidraProvider,
    IdaProvider,
    JebProvider,
    RecordedCrashProvider,
)
from rea_mcp.providers.rizin import RizinProvider

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
@pytest.mark.skipif(
    not (_available(ApktoolProvider()) and os.environ.get("REA_APK_FIXTURE")),
    reason="requires apktool + REA_APK_FIXTURE (a real APK)",
)
def test_apktool_real() -> None:
    fixture = Path(os.environ["REA_APK_FIXTURE"])
    result = ApktoolProvider().analyze("decode_android_resources", _target(fixture), {}, None)
    assert result.ok
    assert result.value.result["file_count"] >= 1


@pytest.mark.real_engine
@pytest.mark.skipif(
    not os.environ.get("REA_ADB_DEVICE"), reason="requires REA_ADB_DEVICE + adb device"
)
def test_adb_real_devices(elf_file: Path) -> None:
    result = AdbProvider().analyze("list_adb_devices", _target(elf_file), {}, None)
    assert result.ok
    assert "devices" in result.value.result


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
    provider = KunaProvider()
    target = _target(elf_file)
    procedures = provider.analyze("list_procedures", target, {}, None)
    assert procedures.ok
    records = procedures.value.result["procedures"]["functions"]
    if not records:
        return
    result = provider.analyze("kuna_decompile", target, {"function": records[0]["name"]}, None)
    assert result.ok


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (_available(GhidraProvider()) and os.environ.get("REA_ELF_FIXTURE")),
    reason="requires pyhidra + Ghidra + JDK + REA_ELF_FIXTURE (a real ELF)",
)
def test_ghidra_real() -> None:
    fixture = Path(os.environ["REA_ELF_FIXTURE"])
    result = GhidraProvider().analyze("ghidra_analyze", _target(fixture), {}, None)
    assert result.ok
    assert result.value.result["function_count"] >= 1


@pytest.mark.real_engine
@pytest.mark.skipif(not _available(FridaProvider()), reason="requires the optional frida package")
def test_frida_real_devices(elf_file: Path) -> None:
    result = FridaProvider().analyze("list_frida_devices", _target(elf_file), {}, None)
    assert result.ok
    assert isinstance(result.value.result["devices"], list)


def _browser_present() -> bool:
    candidates = [
        Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")),
        Path.home() / ".cache" / "ms-playwright",
        Path.home() / "Library" / "Caches" / "ms-playwright",
    ]
    return any(str(path) and any(path.glob("chromium-*")) for path in candidates if path)


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (_available(BrowserProvider()) and _browser_present()),
    reason="requires playwright + an installed browser",
)
def test_browser_real(elf_file: Path, tmp_path: Path) -> None:
    url = os.environ.get("REA_BROWSER_TEST_URL")
    if not url:
        page = tmp_path / "page.html"
        page.write_text(
            "<html><head><title>REA Test Page</title></head><body></body></html>",
            encoding="utf-8",
        )
        url = page.as_uri()
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


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (_available(JadxProvider()) and os.environ.get("REA_APK_FIXTURE")),
    reason="requires jadx + REA_APK_FIXTURE (a real APK)",
)
def test_jadx_real() -> None:
    fixture = Path(os.environ["REA_APK_FIXTURE"])
    result = JadxProvider().analyze("decompile_android_apk", _target(fixture), {}, None)
    assert result.ok
    assert result.value.result["java_file_count"] >= 1


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (_available(ApktoolProvider()) and os.environ.get("REA_APK_FIXTURE")),
    reason="requires apktool + REA_APK_FIXTURE (a real APK)",
)
def test_apktool_smali_real() -> None:
    fixture = Path(os.environ["REA_APK_FIXTURE"])
    result = ApktoolProvider().analyze("decode_android_smali", _target(fixture), {}, None)
    assert result.ok
    assert result.value.result["smali_count"] >= 1


@pytest.mark.real_engine
@pytest.mark.skipif(not _available(FridaProvider()), reason="requires the optional frida package")
def test_frida_real_processes(elf_file: Path) -> None:
    result = FridaProvider().analyze("list_frida_processes", _target(elf_file), {}, None)
    assert result.ok
    assert isinstance(result.value.result["processes"], list)


@pytest.mark.real_engine
@pytest.mark.skipif(not _available(IdaProvider()), reason="requires REA_IDA_MCP_URL")
def test_ida_real(elf_file: Path) -> None:
    result = IdaProvider().analyze("ida_analyze", _target(elf_file), {}, None)
    assert result.ok


@pytest.mark.real_engine
@pytest.mark.skipif(not _available(JebProvider()), reason="requires REA_JEB_MCP_URL")
def test_jeb_real(elf_file: Path) -> None:
    result = JebProvider().analyze("jeb_analyze", _target(elf_file), {}, None)
    assert result.ok


def test_ida_mcp_stdio(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, elf_file: Path) -> None:
    import json
    import sys

    script = tmp_path / "ida_fake.py"
    script.write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        'server = FastMCP("ida-fake")\n'
        '@server.tool(name="get_metadata")\n'
        "def get_metadata() -> dict:\n"
        '    return {"arch": "x86_64", "name": "demo"}\n'
        '@server.tool(name="lookup_funcs")\n'
        "def lookup_funcs(queries: list[str]) -> dict:\n"
        '    return {"functions": [{"name": queries[0], "address": "0x1000"}]}\n'
        '@server.tool(name="decompile_function")\n'
        "def decompile_function(address: str) -> dict:\n"
        '    return {"pseudocode": f"// decompiled {address}"}\n'
        '@server.tool(name="list_functions")\n'
        "def list_functions(offset: int = 0, count: int = 100) -> dict:\n"
        '    return {"functions": [{"name": "main", "address": "0x1000"}]}\n'
        '@server.tool(name="get_xrefs_to")\n'
        "def get_xrefs_to(address: str) -> dict:\n"
        '    return {"xrefs": [{"from": "0x2000", "to": address}]}\n'
        'if __name__ == "__main__":\n'
        '    server.run(transport="stdio")\n',
        encoding="utf-8",
    )
    config = tmp_path / "ida.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"ida-pro-mcp": {"command": sys.executable, "args": [str(script)]}}}
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("REA_IDA_MCP_CONFIG", str(config))
    target = _target(elf_file)
    metadata = IdaProvider().analyze("ida_analyze", target, {}, None)
    assert metadata.ok
    assert metadata.value.result["arch"] == "x86_64"
    decompiled = IdaProvider().analyze("ida_decompile", target, {"function": "main"}, None)
    assert decompiled.ok
    assert "decompiled 0x1000" in decompiled.value.result["pseudocode"]


def _fake_script(tmp_path: Path, name: str, body: str) -> Path:
    script = tmp_path / name
    script.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    script.chmod(0o755)
    return script


_APKTOOL_FAKE = """
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
mkdir -p "$out/res/values" "$out/res/values-de" "$out/smali/com/example"
printf '<resources><string name="hello">Hello</string></resources>\n' > "$out/res/values/strings.xml"
printf '<resources><string name="hello">Hallo</string></resources>\n' > "$out/res/values-de/strings.xml"
printf '.class public Lcom/example/Main;\\n' > "$out/smali/com/example/Main.smali"
printf '<manifest/>\\n' > "$out/AndroidManifest.xml"
"""

_JADX_FAKE = """
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-d" ]; then out="$arg"; fi
  prev="$arg"
done
mkdir -p "$out/sources/com/example"
printf 'package com.example; public class Main {}\\n' > "$out/sources/com/example/Main.java"
"""

_ADB_FAKE = """
if [ "$1" = "-s" ]; then shift 2; fi
if [ "$1" = "devices" ]; then
  echo "List of devices attached"
  echo "emulator-5554 device product:sdk model:Pixel"
  exit 0
fi
if [ "$1" = "shell" ]; then
  shift
  if [ "$1" = "pm" ] && [ "$2" = "list" ]; then
    echo "package:com.example.app"
    exit 0
  fi
  if [ "$1" = "dumpsys" ]; then
    echo "Package [com.example.app]"
    echo "versionName=1.0"
    exit 0
  fi
  echo "shell-output:$*"
  exit 0
fi
exit 0
"""


def test_apktool_decode_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, apk_file: Path
) -> None:
    script = _fake_script(tmp_path, "apktool", _APKTOOL_FAKE)
    monkeypatch.setenv("REA_APKTOOL_COMMAND", str(script))
    resources = ApktoolProvider().analyze("decode_android_resources", _target(apk_file), {}, None)
    assert resources.ok
    assert resources.value.result["file_count"] >= 3
    smali = ApktoolProvider().analyze("decode_android_smali", _target(apk_file), {}, None)
    assert smali.ok
    assert smali.value.result["smali_count"] == 1
    assert smali.value.result["manifest_decoded"] is True
    assert smali.value.result["resource_files"] >= 1


def test_jadx_decompile_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, apk_file: Path
) -> None:
    script = _fake_script(tmp_path, "jadx", _JADX_FAKE)
    monkeypatch.setenv("REA_JADX", str(script))
    apk = JadxProvider().analyze("decompile_android_apk", _target(apk_file), {}, None)
    assert apk.ok
    assert apk.value.result["java_file_count"] == 1
    decompiled = JadxProvider().analyze(
        "decompile_android_class",
        _target(apk_file),
        {"class": "com.example.Main"},
        None,
    )
    assert decompiled.ok
    assert "class Main" in decompiled.value.result["source"]


def test_adb_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, elf_file: Path) -> None:
    script = _fake_script(tmp_path, "adb", _ADB_FAKE)
    monkeypatch.setenv("REA_ADB_PATH", str(script))
    devices = AdbProvider().analyze("list_adb_devices", _target(elf_file), {}, None)
    assert devices.ok
    assert devices.value.result["devices"][0]["serial"] == "emulator-5554"
    packages = AdbProvider().analyze(
        "list_adb_packages", _target(elf_file), {"serial": "emulator-5554"}, None
    )
    assert packages.ok
    assert packages.value.result["packages"][0]["package"] == "com.example.app"
    info = AdbProvider().analyze(
        "android_app_info",
        _target(elf_file),
        {"serial": "emulator-5554", "package": "com.example.app"},
        None,
    )
    assert info.ok
    assert any("Package" in line for line in info.value.result["lines"])
    shell = AdbProvider().analyze(
        "adb_shell",
        _target(elf_file),
        {"command": ["getprop", "ro.build.version.sdk"]},
        None,
    )
    assert shell.ok
    assert shell.value.result["lines"] == ["shell-output:getprop ro.build.version.sdk"]


def test_ghidra_analyze_with_fake_pyhidra(monkeypatch: pytest.MonkeyPatch, elf_file: Path) -> None:
    import sys
    import types

    class _Function:
        def __init__(self, name: str) -> None:
            self._name = name

        def getName(self) -> str:
            return self._name

    class _FunctionManager:
        def getFunctions(self, forward: bool) -> list[_Function]:
            del forward
            return [_Function("main"), _Function("helper")]

    class _Language:
        def toString(self) -> str:
            return "x86:LE:64:default"

    class _Program:
        def getLanguageID(self) -> _Language:
            return _Language()

        def getFunctionManager(self) -> _FunctionManager:
            return _FunctionManager()

    events: list[tuple[object, ...]] = []

    class _FlatApi:
        def getCurrentProgram(self) -> _Program:
            return _Program()

        def getFunction(self, name: str) -> None:
            del name
            return None

        def toAddr(self, value: int) -> int:
            return value

        def createLabel(self, address: int, name: str) -> None:
            events.append(("label", address, name))

        def addEntryPoint(self, address: int) -> None:
            events.append(("entry", address))

    class _Context:
        def __enter__(self) -> _FlatApi:
            return _FlatApi()

        def __exit__(self, *args: object) -> bool:
            del args
            return False

    captured: dict[str, object] = {}

    def _open(path: str, **kwargs: object) -> object:
        captured.update(kwargs)
        return _Context()

    fake_pyhidra = types.SimpleNamespace(open_program=_open)
    monkeypatch.setitem(sys.modules, "pyhidra", fake_pyhidra)
    monkeypatch.setattr(
        "rea_mcp.providers.optional_engines.optional_import",
        lambda name: fake_pyhidra if name == "pyhidra" else None,
    )
    result = GhidraProvider().analyze(
        "ghidra_analyze",
        _target(elf_file),
        {
            "language": "68000:BE:32:default",
            "compiler": "default",
            "entry": "0x1000",
        },
        None,
    )
    assert captured == {
        "language": "68000:BE:32:default",
        "compiler": "default",
    }
    assert events == [("label", 0x1000, "rea_entry"), ("entry", 0x1000)]
    assert result.ok
    assert result.value.result["language"] == "x86:LE:64:default"
    assert result.value.result["function_count"] == 2
    assert result.value.result["functions"] == ["main", "helper"]


def test_jeb_mcp_http(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, elf_file: Path) -> None:
    import importlib.util
    import socket
    import subprocess
    import sys
    import time

    if importlib.util.find_spec("uvicorn") is None:
        pytest.skip("uvicorn is unavailable")

    script = tmp_path / "jeb_fake.py"
    script.write_text(
        "import sys\n"
        "import uvicorn\n"
        "from mcp.server.fastmcp import FastMCP\n"
        'server = FastMCP("jeb-fake")\n'
        '@server.tool(name="get_client_information")\n'
        "def get_client_information() -> dict:\n"
        '    return {"engine": "jeb", "version": "5"}\n'
        '@server.tool(name="open_project")\n'
        "def open_project(path: str) -> dict:\n"
        '    return {"project": path}\n'
        '@server.tool(name="list_units")\n'
        "def list_units() -> dict:\n"
        '    return {"units": ["MainActivity"]}\n'
        '@server.tool(name="decompile_code_item")\n'
        "def decompile_code_item(item: str) -> dict:\n"
        '    return {"source": f"// {item}"}\n'
        'if __name__ == "__main__":\n'
        '    uvicorn.run(server.streamable_http_app(), host="127.0.0.1", port=int(sys.argv[1]), log_level="error")\n',
        encoding="utf-8",
    )
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    process = subprocess.Popen([sys.executable, str(script), str(port)])
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.skip("fake JEB MCP server did not start")
        monkeypatch.setenv("REA_JEB_MCP_URL", f"http://127.0.0.1:{port}/mcp")
        target = _target(elf_file)
        info = JebProvider().analyze("jeb_analyze", target, {}, None)
        assert info.ok
        assert info.value.result["engine"] == "jeb"
        units = JebProvider().analyze("list_jeb_units", target, {}, None)
        assert units.ok
        assert units.value.result["units"] == ["MainActivity"]
    finally:
        process.terminate()
        process.wait(timeout=10)


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (_available(AndroidDeepProvider()) and os.environ.get("REA_APK_FIXTURE")),
    reason="requires JADX + REA_APK_FIXTURE (a real APK)",
)
def test_android_deep_real() -> None:
    fixture = Path(os.environ["REA_APK_FIXTURE"])
    target = _target(fixture)
    search = AndroidDeepProvider().analyze(
        "search_android_classes", target, {"query": "Foobar"}, None
    )
    assert search.ok
    assert search.value.result["match_count"] >= 1
    inspected = AndroidDeepProvider().analyze(
        "inspect_android_class", target, {"class_name": "com.foobar.foo.Foobar"}, None
    )
    assert inspected.ok
    assert "class Foobar" in inspected.value.result["source"]
    method = AndroidDeepProvider().analyze(
        "inspect_android_method",
        target,
        {"class_name": "com.foobar.foo.Foobar", "method": "somemethod"},
        None,
    )
    assert method.ok
    assert "somemethod" in method.value.result["snippet"]
    references = AndroidDeepProvider().analyze(
        "trace_android_references", target, {"query": "somemethod"}, None
    )
    assert references.ok
    assert references.value.result["match_count"] >= 1


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (_available(RizinProvider()) and os.environ.get("REA_ELF_FIXTURE")),
    reason="requires rzpipe + rizin + REA_ELF_FIXTURE",
)
def test_rizin_native_proxy_real() -> None:
    target = _target(Path(os.environ["REA_ELF_FIXTURE"]))
    provider = RizinProvider()
    segments = provider.analyze("list_segments", target, {"limit": 5}, None)
    assert segments.ok and segments.value.result["segments"]
    procedures = provider.analyze("list_procedures", target, {"limit": 5}, None)
    assert procedures.ok and procedures.value.result["procedures"]
    navigated = provider.analyze("goto_address", target, {"address": "entry0"}, None)
    assert navigated.ok
    bookmarked = provider.analyze(
        "set_bookmark", target, {"name": "entry", "address": "entry0"}, None
    )
    assert bookmarked.ok and "entry" in bookmarked.value.result["bookmarks"]
    context = provider.analyze("get_navigation_context", target, {"address": "entry0"}, None)
    assert context.ok
    pseudocode = provider.analyze("procedure_pseudo_code", target, {"function": "entry0"}, None)
    assert pseudocode.ok
    commented = provider.analyze(
        "set_comment", target, {"address": "entry0", "comment": "rea"}, None
    )
    assert commented.ok
    imports = provider.analyze("inspect_native_api", target, {"limit": 5}, None)
    assert imports.ok


@pytest.mark.real_engine
@pytest.mark.skipif(
    not (_available(RizinProvider()) and os.environ.get("REA_ELF_FIXTURE")),
    reason="requires rzpipe + rizin + REA_ELF_FIXTURE",
)
def test_rizin_debug_session_real() -> None:
    target = _target(Path(os.environ["REA_ELF_FIXTURE"]))
    provider = DebugSessionProvider()
    executed = provider.analyze("execute_rizin_command", target, {"command": "ij"}, None)
    assert executed.ok and executed.value.result["output"]
    started = provider.analyze("start_rizin_debug_session", target, {}, None)
    assert started.ok
    session_id = started.value.result["session_id"]
    status = provider.analyze(
        "rizin_debug_session_status", target, {"session_id": session_id}, None
    )
    assert status.ok
    closed = provider.analyze("close_rizin_debug_session", target, {"session_id": session_id}, None)
    assert closed.ok


def test_apktool_string_tables(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, apk_file: Path
) -> None:
    script = _fake_script(tmp_path, "apktool", _APKTOOL_FAKE)
    monkeypatch.setenv("REA_APKTOOL_COMMAND", str(script))
    result = ApktoolProvider().analyze(
        "decode_android_resources",
        _target(apk_file),
        {"include_strings": True, "locales": ["de"], "string_tables_only": True},
        None,
    )
    assert result.ok
    data = result.value.result
    assert data["strings"] == []
    assert data["locales"] == ["de"]
    tables = {table["locale"]: table for table in data["string_tables"]}
    assert set(tables) == {None, "de"}
    assert tables[None]["strings"][0]["value"] == "Hello"
    assert tables["de"]["strings"][0]["value"] == "Hallo"


def test_jadx_operation_timeout_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from rea_mcp.providers.engines import _jadx_operation_timeout

    monkeypatch.delenv("REA_JADX_OPERATION_TIMEOUT_MS", raising=False)
    assert _jadx_operation_timeout() == 120.0
    monkeypatch.setenv("REA_JADX_OPERATION_TIMEOUT_MS", "5000")
    assert _jadx_operation_timeout() == 5.0
    monkeypatch.setenv("REA_JADX_OPERATION_TIMEOUT_MS", "not-a-number")
    assert _jadx_operation_timeout() == 120.0


_KUNA_FAKE = """
cmd="$1"
case "$cmd" in
  functions) echo '[{"name":"main","address":"0x1000"},{"name":"helper","address":"0x2000"}]' ;;
  strings) echo '[{"value":"hello","address":"0x3000"}]' ;;
  xrefs) echo '[{"from":"0x4000","to":"0x1000"}]' ;;
  decompile) echo '// pseudocode' ;;
  decompile-graph) echo '[{"from":"0x1000","to":"0x2000"}]' ;;
  decompile-project)
    out=""
    prev=""
    for arg in "$@"; do
      if [ "$prev" = "-o" ]; then out="$arg"; fi
      prev="$arg"
    done
    mkdir -p "$out"
    printf 'main:\n  nop\n' > "$out/main.asm"
    ;;
  *) echo '{}' ;;
esac
"""


def test_kuna_operations_fake(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, elf_file: Path
) -> None:
    script = _fake_script(tmp_path, "kuna", _KUNA_FAKE)
    monkeypatch.setenv("REA_KUNA_COMMAND", str(script))
    target = _target(elf_file)
    provider = KunaProvider()
    procedures = provider.analyze("list_procedures", target, {}, None)
    assert procedures.ok and procedures.value.result["count"] == 2
    search = provider.analyze("search_procedures", target, {"query": "help"}, None)
    assert search.ok and search.value.result["count"] == 1
    address = provider.analyze("procedure_address", target, {"function": "main"}, None)
    assert address.ok and address.value.result["address"] == "0x1000"
    named = provider.analyze("address_name", target, {"address": "0x1000"}, None)
    assert named.ok and named.value.result["name"] == "main"
    pseudocode = provider.analyze("procedure_pseudo_code", target, {"function": "main"}, None)
    assert pseudocode.ok and "pseudocode" in pseudocode.value.result
    callers = provider.analyze("procedure_callers", target, {"function": "main"}, None)
    assert callers.ok and callers.value.result["xrefs"]
    strings = provider.analyze("list_strings", target, {}, None)
    assert strings.ok and strings.value.result["strings"]
    string_search = provider.analyze("search_strings", target, {"query": "hell"}, None)
    assert string_search.ok and string_search.value.result["count"] == 1
    callees = provider.analyze("procedure_callees", target, {}, None)
    assert callees.ok and callees.value.result["callees"]
    xrefs = provider.analyze("xrefs", target, {"address": "0x1000"}, None)
    assert xrefs.ok and xrefs.value.result["xrefs"]
    documents = provider.analyze("list_documents", target, {}, None)
    assert documents.ok and documents.value.result["documents"]
    assembly = provider.analyze("procedure_assembly", target, {"function": "main"}, None)
    assert assembly.ok
    assert "nop" in assembly.value.result["assembly"]


def test_kuna_raw_image_arguments(tmp_path: Path) -> None:
    from rea_mcp.domain.binary_target import parse_binary_target
    from rea_mcp.providers.engines import _kuna_raw_args

    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x90" * 64)
    target = parse_binary_target(raw, format_hint="raw-binary")
    assert target.ok
    arguments = _kuna_raw_args(
        target.value,
        {"target": "x86:LE:64:default", "base": "0x100000000", "entry": "0x100000010"},
    )
    assert arguments == [
        "--raw-image",
        "--target",
        "x86:LE:64:default",
        "--base",
        "0x100000000",
        "--entry",
        "0x100000010",
    ]
    assert _kuna_raw_args(target.value, {"address": "0x10"}, include_entry=False) == [
        "--raw-image",
        "--target",
        "x86:LE:64:default",
        "--base",
        "0x0",
    ]
