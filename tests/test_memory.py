from agent.extract import parse_error_report
from agent.llm import MockLLM
from agent.memory import (
    Lesson,
    MemoryStore,
    build_lesson,
    classify_format,
    default_note,
    reflect_lesson,
    trajectory_summary,
)


CRASH = parse_error_report(
    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/freetype2/src/parse.c:10:5 in parse\n"
)


def test_classify_format_by_project():
    assert classify_format("freetype2", []) == "font"
    assert classify_format("libredwg", []) == "dwg"
    assert classify_format("ndpi", []) == "network"
    assert classify_format("mruby", []) == "script"
    assert classify_format("unknownproj", ["/a/input.ttf"]) == "font"
    assert classify_format("unknownproj", []) == "other"


def test_build_lesson_fields():
    lesson = build_lesson(
        "arvo:1", "freetype2", CRASH,
        input_format="font", success=True, solved_by="fuzz",
    )
    assert lesson.bug_class == "heap-buffer-overflow"
    assert lesson.sanitizer == "AddressSanitizer"
    assert lesson.crash_func == "parse"
    assert lesson.input_format == "font"
    assert lesson.success is True


def test_memory_record_retrieve_roundtrip(tmp_path):
    store = MemoryStore(tmp_path / "memory.json")
    store.record(build_lesson(
        "arvo:1", "freetype2", CRASH, input_format="font",
        success=False, error="static analysis stuck",
    ))
    store.save()
    # reload from disk
    store2 = MemoryStore(tmp_path / "memory.json").load()
    hits = store2.retrieve(input_format="font", bug_class="heap-buffer-overflow")
    assert len(hits) == 1
    assert hits[0].project == "freetype2"


def test_memory_retrieve_relevance_ranking(tmp_path):
    store = MemoryStore()
    store.record(build_lesson("a", "freetype2", CRASH, input_format="font", success=True, solved_by="fuzz"))
    store.record(build_lesson("b", "libxml2", CRASH, input_format="xml", success=False))
    hits = store.retrieve(input_format="font")
    assert hits and hits[0].project == "freetype2"
    # unrelated format yields nothing
    assert store.retrieve(input_format="audio") == []


def test_memory_render():
    store = MemoryStore()
    store.record(build_lesson("a", "freetype2", CRASH, input_format="font", success=True, solved_by="fuzz", note="fuzz worked"))
    text = store.render(store.retrieve(input_format="font"))
    assert "freetype2" in text
    assert "SOLVED" in text


def test_default_note():
    assert "fuzz" in default_note(True, "fuzz")
    assert "static analysis insufficient" in default_note(False, "")


def test_reflect_lesson_uses_model():
    llm = MockLLM(["use a CFF2 seed font and fuzz longer"])
    lesson = reflect_lesson(
        llm, project="freetype2", input_format="font", description="d",
        crash=CRASH, success=False, solved_by="", error="stuck",
        trajectory_summary="- grep: x\n- submit_poc: exit 0",
    )
    assert "CFF2" in lesson


def test_reflect_lesson_falls_back_on_trivial():
    llm = MockLLM(["..."])
    lesson = reflect_lesson(
        llm, project="freetype2", input_format="font", description="d",
        crash=CRASH, success=False, solved_by="", error="stuck",
        trajectory_summary="",
    )
    assert "static analysis insufficient" in lesson


def test_trajectory_summary():
    traj = [{"tool": "grep", "result": "match"}, {"tool": "submit_poc", "result": "exit 0"}]
    text = trajectory_summary(traj)
    assert "- grep:" in text
    assert "- submit_poc:" in text
