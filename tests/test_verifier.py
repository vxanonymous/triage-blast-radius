from __future__ import annotations

from pathlib import Path

import pytest
from slimconfig import build_output, plain_output

import verifier
from contract import TASKS, TOOLS, CountInput, GenerateInput, Task, Tool
from plugin import count_distinct, generate_traffic

HEADER = "ts,client_ip,user_id,endpoint,status,latency_ms\n"
ENDPOINTS = [
    "/api/search",
    "/api/products",
    "/api/cart",
    "/api/login",
    "/api/checkout",
    "/api/profile",
    "/api/reviews",
    "/api/health",
]


# The verifier gets contract instances, as NanoAgent's sandbox builds them from JSON.
def verify_input(tool: str, value: dict) -> dict:
    return verifier.verify_input(tool, build_output(value, TOOLS[Tool(tool)][0]))


def verify_output(tool: str, given: dict, made: dict, workspace: Path) -> dict:
    classes = TOOLS[Tool(tool)]
    return verifier.verify_output(tool, build_output(given, classes[0]), build_output(made, classes[1]), str(workspace))


def verify_task(task: str, arguments: dict, output: dict, workspace: Path) -> dict:
    given, made = TASKS[Task(task)]
    return verifier.verify_task(task, build_output(arguments, given), build_output(output, made), None, str(workspace))


def generated(workspace: Path, seed: int = 2, requests: int = 20_000) -> tuple[dict, dict]:
    given = {"seed": seed, "requests": requests, "destination": "traffic"}
    return given, plain_output(generate_traffic(GenerateInput(**given), workspace))


def distinct(
    workspace: Path,
    file: str,
    endpoint: str = "",
    precision: int = 12,
    status_class: str = "5xx",
    field: str = "user_id",
) -> tuple[dict, dict]:
    given = {"file": file, "field": field, "status_class": status_class, "endpoint": endpoint, "precision": precision}
    built = build_output(given, CountInput)
    return given, plain_output(count_distinct(built, workspace))


# generate_traffic


def test_approves_a_generated_log(tmp_path: Path) -> None:
    given, made = generated(tmp_path)
    assert verify_output("generate_traffic", given, made, tmp_path)["valid"] is True
    assert verify_task("generate-traffic", given, made, tmp_path)["valid"] is True


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"file": "traffic/traffic-3-20000.csv"}, "not saved as"),
        ({"sha256": "0" * 64}, "sha256"),
        ({"requests": 19_999}, "requests"),
        ({"columns": ["ts"]}, "columns"),
    ],
)
def test_refuses_a_wrong_generate_output(tmp_path: Path, changes: dict, message: str) -> None:
    given, made = generated(tmp_path)
    verdict = verify_output("generate_traffic", given, made | changes, tmp_path)
    assert verdict["valid"] is False and message in verdict["message"]


def test_refuses_a_missing_or_tampered_log(tmp_path: Path) -> None:
    given, made = generated(tmp_path)
    target = tmp_path / made["file"]
    target.write_text(target.read_text() + "2026-11-01T00:00:00Z,10.0.0.1,u0001,/api/x,200,5\n")
    assert "sha256" in verify_output("generate_traffic", given, made, tmp_path)["message"]
    target.unlink()
    assert "not in the workspace" in verify_output("generate_traffic", given, made, tmp_path)["message"]


# count_distinct


@pytest.mark.parametrize(
    ("endpoint", "precision", "status_class", "field"),
    [
        ("", 12, "5xx", "user_id"),
        ("/api/cart", 12, "5xx", "user_id"),
        ("", 4, "any", "user_id"),
        ("", 16, "any", "client_ip"),
        ("/api/search", 10, "4xx", "endpoint"),
        ("", 8, "2xx", "user_id"),
    ],
)
def test_approves_the_hyperloglog_estimate(tmp_path: Path, endpoint, precision, status_class, field) -> None:
    _, log = generated(tmp_path)
    given, made = distinct(tmp_path, log["file"], endpoint, precision, status_class, field)
    assert made["registers"] == 2**precision
    assert verify_output("count_distinct", given, made, tmp_path)["valid"] is True
    assert verify_task("count-affected", given, made, tmp_path)["valid"] is True


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"estimate": 1}, "estimate"),
        ({"rows_counted": 1}, "rows_counted"),
        ({"registers": 1024}, "registers"),
        ({"nonzero_registers": 3}, "nonzero_registers"),
        ({"standard_error": 0.1}, "standard_error"),
        ({"precision": 10}, "not the one asked"),
        ({"endpoint": "/api/cart"}, "not the one asked"),
        ({"field": "client_ip"}, "not the one asked"),
        ({"status_class": "4xx"}, "not the one asked"),
    ],
)
def test_refuses_a_wrong_count(tmp_path: Path, changes: dict, message: str) -> None:
    _, log = generated(tmp_path)
    given, made = distinct(tmp_path, log["file"])
    verdict = verify_output("count_distinct", given, made | changes, tmp_path)
    assert verdict["valid"] is False and message in verdict["message"]


def test_refuses_an_estimate_off_by_one(tmp_path: Path) -> None:
    # Within the sanity bound, but not the HyperLogLog's own number.
    _, log = generated(tmp_path)
    given, made = distinct(tmp_path, log["file"])
    verdict = verify_output("count_distinct", given, made | {"estimate": made["estimate"] + 1}, tmp_path)
    assert verdict["valid"] is False and verdict["details"]["problems"] == [
        f"estimate is {made['estimate'] + 1}, but the HyperLogLog gives {made['estimate']}"
    ]


def test_refuses_a_far_estimate_on_both_counts(tmp_path: Path) -> None:
    _, log = generated(tmp_path)
    given, made = distinct(tmp_path, log["file"])
    problems = verify_output("count_distinct", given, made | {"estimate": 10_000}, tmp_path)["details"]["problems"]
    assert len(problems) == 2 and "too far from the exact" in problems[1]


def test_an_empty_selection_estimates_zero(tmp_path: Path) -> None:
    (tmp_path / "ok.csv").write_text(HEADER + "2026-10-31T12:00:00Z,10.0.0.1,u0001,/api/a,200,5\n")
    given, made = distinct(tmp_path, "ok.csv", precision=4)
    assert made["rows_counted"] == 0 and made["estimate"] == 0 and made["nonzero_registers"] == 0
    assert verify_output("count_distinct", given, made, tmp_path)["valid"] is True
    assert verify_output("count_distinct", given, made | {"estimate": 1}, tmp_path)["valid"] is False


def test_a_tampered_log_changes_the_truth(tmp_path: Path) -> None:
    _, log = generated(tmp_path)
    given, made = distinct(tmp_path, log["file"], "/api/cart")
    target = tmp_path / log["file"]
    extra = "".join(f"2026-11-01T00:00:00Z,10.0.0.1,x{index},/api/cart,500,5\n" for index in range(50))
    target.write_text(target.read_text() + extra)
    assert verify_output("count_distinct", given, made, tmp_path)["valid"] is False


def test_refuses_a_malformed_log(tmp_path: Path) -> None:
    given = {"file": "bad.csv", "field": "user_id", "status_class": "any", "endpoint": "", "precision": 4}
    made = given | {
        "rows_counted": 0,
        "registers": 16,
        "nonzero_registers": 0,
        "estimate": 0,
        "standard_error": 0.26,
    }
    (tmp_path / "bad.csv").write_text("not,a,log\n")
    assert "header" in verify_output("count_distinct", given, made, tmp_path)["message"]
    (tmp_path / "bad.csv").write_text(HEADER + "2026-10-31T12:00:00Z,10.0.0.1,/api/a,200\n")
    assert "columns" in verify_output("count_distinct", given, made, tmp_path)["message"]
    (tmp_path / "bad.csv").unlink()
    assert "not in the workspace" in verify_output("count_distinct", given, made, tmp_path)["message"]


def test_checks_what_the_types_cannot_say() -> None:
    good = {"file": "traffic/t.csv", "field": "user_id", "status_class": "5xx", "endpoint": "", "precision": 12}
    assert verify_input("count_distinct", good)["valid"] is True
    for fine in ({"precision": 4}, {"precision": 16}, {"endpoint": "/api/cart"}):
        assert verify_input("count_distinct", good | fine)["valid"] is True, fine
    for bad in (
        {"precision": 3},
        {"precision": 17},
        {"endpoint": "api/cart"},
        {"endpoint": "/cart"},
        {"file": "../t.csv"},
        {"file": "/abs/t.csv"},
        {"file": "t.txt"},
    ):
        assert verify_input("count_distinct", good | bad)["valid"] is False, bad
    generate = {"seed": 1, "requests": 1000, "destination": "traffic"}
    assert verify_input("generate_traffic", generate)["valid"] is True
    assert verify_input("generate_traffic", generate | {"requests": 200_000})["valid"] is True
    for bad in ({"requests": 999}, {"requests": 200_001}, {"destination": "/abs"}, {"destination": "../x"}):
        assert verify_input("generate_traffic", generate | bad)["valid"] is False, bad


# largest-blast-radius


def blast(workspace: Path, seed: int = 2, requests: int = 20_000) -> tuple[dict, dict]:
    """What a correct agent submits: generate, one count_distinct per endpoint, then one over every endpoint."""
    _, log = generated(workspace, seed, requests)
    estimates = {endpoint: distinct(workspace, log["file"], endpoint)[1]["estimate"] for endpoint in ENDPOINTS}
    widest = max(ENDPOINTS, key=lambda endpoint: estimates[endpoint])
    _, total = distinct(workspace, log["file"])
    output = {
        "file": log["file"],
        "endpoint": widest,
        "affected_estimate": estimates[widest],
        "total_affected_estimate": total["estimate"],
    }
    return {"seed": seed, "requests": requests}, output


@pytest.mark.parametrize(
    ("seed", "requests", "endpoint"),
    [(2, 20_000, "/api/cart"), (7, 20_000, "/api/checkout"), (1, 5000, "/api/login"), (4, 1000, "/api/login")],
)
def test_approves_the_largest_blast_radius(tmp_path: Path, seed: int, requests: int, endpoint: str) -> None:
    arguments, output = blast(tmp_path, seed, requests)
    assert output["endpoint"] == endpoint
    verdict = verify_task("largest-blast-radius", arguments, output, tmp_path)
    assert verdict["valid"] is True and verdict["score"] == 1.0 and verdict["details"]["failed"] == []


@pytest.mark.parametrize(
    ("changes", "failed"),
    [
        # Another endpoint's estimate is wrong for it too.
        ({"endpoint": "/api/search"}, ["endpoint", "affected_estimate"]),
        ({"affected_estimate": 1}, ["affected_estimate"]),
        ({"total_affected_estimate": 1}, ["total_affected_estimate"]),
        ({"affected_estimate": 1, "total_affected_estimate": 1}, ["affected_estimate", "total_affected_estimate"]),
    ],
)
def test_refuses_a_wrong_blast_radius_and_scores_what_is_right(tmp_path: Path, changes: dict, failed: list) -> None:
    arguments, output = blast(tmp_path)
    verdict = verify_task("largest-blast-radius", arguments, output | changes, tmp_path)
    assert verdict["valid"] is False and verdict["details"]["failed"] == failed
    assert verdict["score"] == (3 - len(failed)) / 3


def test_a_wrong_endpoint_with_its_own_estimate_only_fails_the_endpoint(tmp_path: Path) -> None:
    arguments, output = blast(tmp_path)
    _, search = distinct(tmp_path, output["file"], "/api/search")
    submitted = output | {"endpoint": "/api/search", "affected_estimate": search["estimate"]}
    verdict = verify_task("largest-blast-radius", arguments, submitted, tmp_path)
    assert verdict["details"]["failed"] == ["endpoint"] and verdict["score"] == 2 / 3


def test_refuses_a_blast_radius_from_another_log_or_none(tmp_path: Path) -> None:
    arguments, output = blast(tmp_path)
    verdict = verify_task("largest-blast-radius", arguments | {"seed": 3}, output, tmp_path)
    assert "not the seed's log" in verdict["message"] and verdict["score"] == 0.0
    (tmp_path / output["file"]).unlink()
    assert "not in the workspace" in verify_task("largest-blast-radius", arguments, output, tmp_path)["message"]


def test_a_log_without_5xx_has_no_blast_radius(tmp_path: Path) -> None:
    (tmp_path / "traffic").mkdir()
    rows = ["2026-10-31T12:00:00Z,10.0.0.1,u0001,/api/a,200,5"] * 1000
    (tmp_path / "traffic" / "traffic-0-1000.csv").write_text(HEADER + "\n".join(rows) + "\n")
    output = {"file": "traffic/traffic-0-1000.csv", "endpoint": "/api/a", "affected_estimate": 0}
    verdict = verify_task(
        "largest-blast-radius", {"seed": 0, "requests": 1000}, output | {"total_affected_estimate": 0}, tmp_path
    )
    assert verdict["valid"] is False and "no 5xx" in verdict["message"]


def test_a_tie_accepts_either_endpoint(tmp_path: Path) -> None:
    rows = ["2026-10-31T12:00:00Z,10.0.0.1,u0001,/api/a,500,5", "2026-10-31T12:00:01Z,10.0.0.1,u0002,/api/b,503,5"]
    rows += ["2026-10-31T12:00:02Z,10.0.0.1,u0003,/api/c,200,5"] * 998
    (tmp_path / "traffic").mkdir()
    (tmp_path / "traffic" / "traffic-0-1000.csv").write_text(HEADER + "\n".join(rows) + "\n")
    output = {"file": "traffic/traffic-0-1000.csv", "affected_estimate": 1, "total_affected_estimate": 2}
    for endpoint in ("/api/a", "/api/b"):
        verdict = verify_task(
            "largest-blast-radius", {"seed": 0, "requests": 1000}, output | {"endpoint": endpoint}, tmp_path
        )
        assert verdict["valid"] is True, endpoint
    verdict = verify_task(
        "largest-blast-radius", {"seed": 0, "requests": 1000}, output | {"endpoint": "/api/c"}, tmp_path
    )
    assert verdict["details"]["failed"] == ["endpoint", "affected_estimate"]
