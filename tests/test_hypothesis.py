from agent.extract import parse_error_report
from agent.hypothesis import bug_class_hypotheses, plan_hypotheses
from agent.llm import MockLLM


HEAP = parse_error_report(
    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/x/src/parse.c:10:5 in parse_image\n"
)


def test_bug_class_hypotheses_grounded_first():
    hyps = bug_class_hypotheses(HEAP)
    assert hyps[0].grounded is True
    assert len(hyps) >= 2
    # a heap-buffer-overflow plan must mention out-of-bounds
    assert any("out-of-bounds" in h.claim for h in hyps)


def test_bug_class_hypotheses_none_crash():
    hyps = bug_class_hypotheses(None)
    assert len(hyps) == 1 and hyps[0].grounded


def test_plan_hypotheses_n_is_one():
    llm = MockLLM([{"hypotheses": []}])
    hyps = plan_hypotheses(llm, description="d", crash=HEAP, harness_file="f.c", n=1)
    assert len(hyps) == 1 and hyps[0].grounded


def test_plan_hypotheses_falls_back_on_bad_llm():
    llm = MockLLM(["not json at all"])
    hyps = plan_hypotheses(llm, description="d", crash=HEAP, harness_file="f.c", n=3)
    # grounded branch always first, then deterministic fallback fills the rest
    assert hyps[0].grounded
    assert len(hyps) >= 2


def test_plan_hypotheses_uses_llm_output():
    llm = MockLLM([{"hypotheses": [{"claim": "oversized count", "input_shape": "big n"}]}])
    hyps = plan_hypotheses(llm, description="d", crash=HEAP, harness_file="f.c", n=3)
    assert hyps[0].grounded
    assert hyps[1].claim == "oversized count"
