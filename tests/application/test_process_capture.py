import sys

from rea_mcp.application.process_capture import capture_process


def test_capture_success() -> None:
    result = capture_process([sys.executable, "-c", "print('hello')"], timeout=15)
    assert result.ok
    assert result.value["stdout"].strip() == "hello"
    assert result.value["exit_code"] == 0
    assert result.value["command"][0] == sys.executable


def test_capture_timeout() -> None:
    result = capture_process([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.4)
    assert result.ok
    assert result.value["timed_out"] is True
