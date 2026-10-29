from pathlib import Path

from agent.verify.matcher import match_jest_output
from contracts import MatchReason

DATA_DIR = Path(__file__).resolve().parent / "data"


def _read_capture(name: str) -> str:
    path = DATA_DIR / name
    assert path.exists(), f"Missing real Jest capture file: {path}"
    return path.read_text(encoding="utf-8")


def test_matcher_accepts_only_true_tagged_failure():
    res = match_jest_output(_read_capture("tagged_failure.json"), "IDOR-INVOICE-READ")
    assert res.matched is True
    assert res.reason == MatchReason.TAG_MATCHED


def test_matcher_rejects_prefix_collision_on_tag():
    res = match_jest_output(_read_capture("tagged_failure.json"), "IDOR-INVOICE")
    assert res.matched is False
    assert res.reason == MatchReason.WRONG_TAG


def test_matcher_rejects_passing_test():
    res = match_jest_output(_read_capture("passing_test.json"), "IDOR-INVOICE-READ")
    assert res.matched is False
    assert res.reason == MatchReason.PASSED


def test_matcher_rejects_missing_module():
    res = match_jest_output(_read_capture("missing_module.json"), "IDOR-INVOICE-READ")
    assert res.matched is False
    assert res.reason == MatchReason.SETUP_ERROR


def test_matcher_rejects_jest_timeout_and_sandbox_timeout():
    res = match_jest_output(_read_capture("jest_timeout.json"), "IDOR-INVOICE-READ")
    assert res.matched is False
    assert res.reason == MatchReason.TIMEOUT

    res_wall = match_jest_output("", "IDOR-INVOICE-READ", timed_out=True)
    assert res_wall.matched is False
    assert res_wall.reason == MatchReason.TIMEOUT


def test_matcher_rejects_port_in_use():
    res = match_jest_output(_read_capture("port_in_use.json"), "IDOR-INVOICE-READ")
    assert res.matched is False
    assert res.reason == MatchReason.SETUP_ERROR


def test_matcher_rejects_wrong_tag_and_no_tag():
    wrong = match_jest_output(_read_capture("wrong_tag.json"), "IDOR-INVOICE-READ")
    assert wrong.matched is False
    assert wrong.reason == MatchReason.WRONG_TAG

    no_tag = match_jest_output(_read_capture("no_tag_failure.json"), "IDOR-INVOICE-READ")
    assert no_tag.matched is False
    assert no_tag.reason == MatchReason.NO_TAG
