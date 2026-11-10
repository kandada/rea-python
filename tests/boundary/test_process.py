import sys

from rea_mcp.process.supervision import run_owned_process


def test_successful_process() -> None:
    result = run_owned_process([sys.executable, "-c", "print('hi')"], timeout=15)
    assert result.ok
    assert result.value.stdout.strip() == "hi"
    assert result.value.exit_code == 0


def test_nonzero_exit_is_observed() -> None:
    result = run_owned_process([sys.executable, "-c", "import sys; sys.exit(3)"], timeout=15)
    assert result.ok
    assert result.value.exit_code == 3


def test_timeout_is_bounded() -> None:
    result = run_owned_process([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    assert result.ok
    assert result.value.timed_out is True
    assert any("deadline" in item for item in result.value.limitations)


def test_output_is_truncated() -> None:
    result = run_owned_process(
        [sys.executable, "-c", "print('x' * 100000)"], timeout=15, max_output_bytes=1024
    )
    assert result.ok
    assert result.value.stdout_truncated is True
    assert len(result.value.stdout) <= 4096


def test_missing_command_is_error() -> None:
    result = run_owned_process(["/nonexistent/binary-xyz"], timeout=5)
    assert not result.ok
    assert result.error.tag == "ProviderAdapterError"


def test_cancellation_is_prompt_and_preserves_output() -> None:
    import threading
    import time

    event = threading.Event()
    timer = threading.Timer(0.3, event.set)
    timer.start()
    started = time.monotonic()
    try:
        result = run_owned_process(
            [
                sys.executable,
                "-c",
                "import time; print('started', flush=True); time.sleep(30)",
            ],
            timeout=30,
            cancel_event=event,
            operation="test_cancel",
        )
    finally:
        timer.cancel()
    elapsed = time.monotonic() - started
    assert not result.ok
    assert result.error.tag == "AnalysisCancelledError"
    assert elapsed < 10
    assert "started" in str(result.error.details.get("stdout"))


def test_split_command_posix_and_empty() -> None:
    from rea_mcp.process.argv import split_command

    assert split_command("python -c 'print(1)'") == ["python", "-c", "print(1)"]
    assert split_command("   ") == []


def test_split_command_keeps_windows_paths(monkeypatch) -> None:
    from rea_mcp.process import argv

    monkeypatch.setattr(argv.os, "name", "nt")
    assert argv.split_command(r"C:\tools\app.exe --flag {prompt}") == [
        r"C:\tools\app.exe",
        "--flag",
        "{prompt}",
    ]
    assert argv.split_command(r'"C:\Program Files\App\app.exe" "a b"') == [
        r"C:\Program Files\App\app.exe",
        "a b",
    ]
