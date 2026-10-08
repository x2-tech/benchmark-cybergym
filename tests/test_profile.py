from agent.profile import (
    TEXT, SIMPLE_BINARY, COMPLEX_BINARY,
    classify_task,
)


def test_text_project():
    assert classify_task("mruby") is TEXT
    assert classify_task("Lua") is TEXT
    assert classify_task("jq") is TEXT


def test_simple_binary_project():
    assert classify_task("binutils") is SIMPLE_BINARY
    assert classify_task("file") is SIMPLE_BINARY
    assert classify_task("graphicsmagick") is SIMPLE_BINARY


def test_complex_project():
    assert classify_task("ffmpeg") is COMPLEX_BINARY
    assert classify_task("mupdf") is COMPLEX_BINARY
    assert classify_task("libtiff") is COMPLEX_BINARY


def test_keyword_fallback():
    assert classify_task("unknown_proj", "Parse the TIFF header") is COMPLEX_BINARY
    assert classify_task("unknown_proj", "Image decoder overflow") is COMPLEX_BINARY


def test_default_fallback():
    assert classify_task("totally_unknown") is SIMPLE_BINARY
    assert classify_task("") is SIMPLE_BINARY


def test_case_insensitive():
    assert classify_task("FFmpeg") is COMPLEX_BINARY
    assert classify_task("MRuby") is TEXT


def test_profile_fields():
    assert TEXT.fuzz_seconds == 0
    assert TEXT.fuzz_primary is False
    assert TEXT.grounded_tool_calls == 30
    assert TEXT.commit_at == 10
    assert SIMPLE_BINARY.fuzz_seconds == 90
    assert SIMPLE_BINARY.fuzz_primary is False
    assert SIMPLE_BINARY.grounded_tool_calls == 30
    assert SIMPLE_BINARY.commit_at == 10
    assert COMPLEX_BINARY.fuzz_seconds == 180
    assert COMPLEX_BINARY.fuzz_primary is True
    assert COMPLEX_BINARY.grounded_tool_calls == 25
    assert COMPLEX_BINARY.commit_at == 8
