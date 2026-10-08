import base64

from agent.agent import (
    _decode_poc,
    _extract_tool_calls,
    _find_harness,
    _flatten_repo,
    _parse_attrs,
    _parse_reply,
    _resolve_source_file,
)
from agent.extract import parse_error_report
from agent.llm import _extract_json


def test_decode_poc_variants():
    assert _decode_poc({"poc_hex": "50 2a 4d"}) == bytes.fromhex("502a4d")
    assert _decode_poc({"poc_hex": "0x50,0x2a"}) == b"P*"
    assert _decode_poc({"poc_b64": "UAAAAA=="}) == b"P\x00\x00\x00"
    assert _decode_poc({"poc_text": "hello"}) == b"hello"
    assert _decode_poc({"analysis": "no poc"}) is None
    assert _decode_poc({"poc_hex": "zz"}) is None


def test_flatten_repo(tmp_path):
    inner = tmp_path / "src-vul"
    inner.mkdir()
    (inner / "x.txt").write_text("x")
    assert _flatten_repo(tmp_path) == inner
    (tmp_path / "top.txt").write_text("t")
    assert _flatten_repo(tmp_path) == tmp_path


def test_resolve_source_file(tmp_path):
    (tmp_path / "file" / "src").mkdir(parents=True)
    (tmp_path / "file" / "src" / "softmagic.c").write_text("x")
    crash = parse_error_report("SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/file/src/softmagic.c:365:9 in match\n")
    assert _resolve_source_file(tmp_path, crash).name == "softmagic.c"


def test_find_harness(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "fuzzme.cc").write_text("int LLVMFuzzerTestOneInput(const char*d, size_t n){return 0;}\n")
    assert _find_harness(tmp_path) == "sub/fuzzme.cc"


def test_find_harness_prefers_target(tmp_path):
    (tmp_path / "fuzz_as.c").write_text("int LLVMFuzzerTestOneInput(const char*d, size_t n){return 0;}\n")
    (tmp_path / "fuzz_readelf.c").write_text("int LLVMFuzzerTestOneInput(const char*d, size_t n){return 0;}\n")
    assert _find_harness(tmp_path, "/out/fuzz_as") == "fuzz_as.c"


def test_parse_attrs():
    assert _parse_attrs('path="a/b.c" offset=3 limit=50') == {"path": "a/b.c", "offset": "3", "limit": "50"}
    assert _parse_attrs("pattern='regexec'") == {"pattern": "regexec"}


def test_parse_reply_json(tmp_path):
    (tmp_path / "a.c").write_text("int x;\n")
    kind, payload = _parse_reply('{"action":"generate","poc_hex":"00ff"}', tmp_path)
    assert kind == "generate" and payload == b"\x00\xff"


def test_parse_reply_tags(tmp_path):
    (tmp_path / "a.c").write_text("int x;\n")
    kind, payload = _parse_reply('<read_file path="a.c" offset=1 limit=5>\n<grep pattern="int">', tmp_path)
    assert kind == "tools"
    joined = "\n".join(payload)
    assert "a.c lines" in joined and "int x" in joined


def test_extract_tool_calls_anthropic_invoke():
    content = (
        "<tool_calls>"
        '<invoke name="read_file">'
        '<parameter name="path" string="true">a/b.c</parameter>'
        '<parameter name="offset">10</parameter>'
        '<parameter name="limit">50</parameter>'
        "</invoke>"
        '<invoke name="grep"><parameter name="pattern">regexec</parameter></invoke>'
        "</tool_calls>"
    )
    calls = _extract_tool_calls(content)
    assert calls[0] == {"tool": "read_file", "path": "a/b.c", "offset": "10", "limit": "50"}
    assert calls[1] == {"tool": "grep", "pattern": "regexec"}


def test_extract_tool_calls_selfclosing_and_echo_skip():
    calls = _extract_tool_calls('<file path="a.c" offset="1" limit="5"/><grep pattern="int"/>')
    assert calls[0]["tool"] == "read_file"
    assert calls[1] == {"tool": "grep", "pattern": "int"}
    # echoes of our own "<file a.c lines 1-5>" output have no path= attr -> skipped
    assert _extract_tool_calls("<file a.c lines 1-5>") == []


def test_extract_json_fences_and_prose():
    assert _extract_json('```json\n{"a":1}\n```') == {"a": 1}
    assert _extract_json('reasoning here {"a": 1} done') == {"a": 1}
    assert _extract_json("not json at all") is None
