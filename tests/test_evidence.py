from agent.evidence import Candidate, EvidenceStore, crash_match_score
from agent.extract import parse_error_report


CRASH = parse_error_report(
    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x/src/parse.c:10:5 in parse_image\n"
    "DEDUP_TOKEN: parse_image--fz_load\n"
)


def test_crash_match_score_exact():
    out = "ERROR: AddressSanitizer: heap-buffer-overflow in parse_image /src/x/src/parse.c:10"
    assert crash_match_score(CRASH, out) >= 0.85


def test_crash_match_score_unrelated_low():
    out = "ERROR: AddressSanitizer: stack-overflow in other_func /src/x/src/other.c:1"
    assert crash_match_score(CRASH, out) < 0.5


def test_crash_match_score_none():
    assert crash_match_score(None, "anything") == 0.0
    assert crash_match_score(CRASH, "") == 0.0


def test_evidence_read_dedup():
    store = EvidenceStore()
    calls = []

    def read_fn(path, offset, limit):
        calls.append((path, offset, limit))
        return "line1\nline2\n"

    text, known = store.read_file("a.c", 1, 2, read_fn)
    assert not known and text == "line1\nline2\n"
    text, known = store.read_file("a.c", 1, 2, read_fn)
    assert known
    assert len(calls) == 1  # second read was a cache hit


def test_evidence_input_dedup():
    store = EvidenceStore()
    assert not store.has_input(b"abc")
    store.record_input(b"abc", "crash")
    assert store.has_input(b"abc")
    assert not store.has_input(b"abcd")


def test_evidence_facts_render():
    store = EvidenceStore()
    store.add_fact("candidate 12345678 crashed vul")
    store.add_fact("candidate 12345678 crashed vul")  # duplicate dropped
    assert store.render_facts() == "- candidate 12345678 crashed vul"


def test_candidate_sha_and_size():
    c = Candidate(poc=b"hello", vul_exit_code=77, vul_output="out", source="fuzz")
    assert c.size == 5
    assert c.sha1 == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
