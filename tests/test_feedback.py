from agent.extract import parse_submit_feedback, parse_error_report, SubmitFeedback
from agent.fuzz import is_trivial_crash


ASAN_OUTPUT = """\
==14==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011
    #0 0x49f6b6 in parse_image /src/mupdf/source/fitz/image.c:120:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/mupdf/source/fitz/image.c:120:5 in parse_image
"""

CRASH = parse_error_report(ASAN_OUTPUT)


def test_crashed_at_target():
    fb = parse_submit_feedback(1, ASAN_OUTPUT, CRASH)
    assert fb.crashed is True
    assert fb.sanitizer_hit is True
    assert fb.target_func_reached is True
    assert fb.error_type_match is True
    assert "target function" in fb.diagnosis


def test_crashed_wrong_func():
    fb = parse_submit_feedback(1, "SIGSEGV in some_other_func", CRASH)
    assert fb.crashed is True
    assert fb.target_func_reached is False
    assert "NOT at the target" in fb.diagnosis


def test_clean_exit():
    fb = parse_submit_feedback(0, "exit 0 nothing interesting", CRASH)
    assert fb.crashed is False
    assert fb.diagnosis.startswith("Clean exit")


def test_sanitizer_no_crash():
    fb = parse_submit_feedback(0, "AddressSanitizer: something detected", CRASH)
    assert fb.crashed is False
    assert fb.sanitizer_hit is True
    assert "refinement" in fb.diagnosis


def test_no_response():
    fb = parse_submit_feedback(None, "", None)
    assert fb.crashed is False
    assert "No response" in fb.diagnosis


def test_signal_detection():
    assert parse_submit_feedback(11, "SIGSEGV at 0x1234", None).signal == "SIGSEGV"
    assert parse_submit_feedback(6, "SIGABRT", None).signal == "SIGABRT"
    assert parse_submit_feedback(7, "SIGBUS", None).signal == "SIGBUS"
    assert parse_submit_feedback(1, "request timeout reached", None).signal == "timeout"


# -- is_trivial_crash --

def test_trivial_null_deref():
    assert is_trivial_crash("null pointer dereference at 0x000000000000")


def test_trivial_sigbus():
    assert is_trivial_crash("SIGBUS blah PC 0x0")


def test_trivial_not_mmaped():
    assert is_trivial_crash("INSTR at addr is NOT_MMAPED")


def test_trivial_signal_11():
    assert is_trivial_crash("signal 11 (SIGSEGV), si_addr = 0x00000000")


def test_real_crash_not_trivial():
    assert not is_trivial_crash(
        "heap-buffer-overflow in parse_image /src/mupdf/source/fitz/image.c:120"
    )
    assert not is_trivial_crash("")
    assert not is_trivial_crash("SIGSEGV at 0xdeadbeef")
