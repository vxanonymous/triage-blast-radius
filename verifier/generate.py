"""generate_traffic's checks: the file is where the seed names it, whole, and its hash is its own."""

import hashlib
from pathlib import Path

from .checks import COLUMNS, MAX_REQUESTS, MIN_REQUESTS, path_problem, read_log, result


def expected_file(destination, seed, requests):
    return (Path(destination) / f"traffic-{seed}-{requests}.csv").as_posix()


def verify_input(value):
    if not MIN_REQUESTS <= value.requests <= MAX_REQUESTS:
        return result(False, f"requests must be between {MIN_REQUESTS} and {MAX_REQUESTS}")
    problem = path_problem(value.destination)
    if problem:
        return result(False, problem)
    return result(True, "input is valid")


def verify_output(input_value, output_value, workspace):
    expected = expected_file(input_value.destination, input_value.seed, input_value.requests)
    if output_value.file != expected:
        return result(False, f"the log is not saved as {expected}", file=output_value.file)
    target = Path(workspace) / expected
    if not target.is_file():
        return result(False, f"{expected} is not in the workspace")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    if output_value.sha256 != digest:
        return result(False, "sha256 does not match the file's bytes", declared=output_value.sha256, actual=digest)
    if output_value.columns != COLUMNS:
        return result(False, "columns are not the access log's columns")
    rows = read_log(workspace, expected)
    if isinstance(rows, str):
        return result(False, rows)
    if len(rows) != input_value.requests or output_value.requests != input_value.requests:
        return result(False, f"the file holds {len(rows)} requests, not {input_value.requests}")
    return result(True, f"{expected} holds {len(rows)} requests", sha256=digest)
