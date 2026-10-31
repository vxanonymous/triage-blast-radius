"""Checks shared by the tool verifiers. Pure functions of their arguments and the files on disk."""

import hashlib
import math
from pathlib import Path

COLUMNS = ["ts", "client_ip", "user_id", "endpoint", "status", "latency_ms"]
MIN_REQUESTS, MAX_REQUESTS = 1000, 200000
MIN_PRECISION, MAX_PRECISION = 4, 16
ENDPOINT_PREFIX = "/api/"


def result(valid, message, *, score=None, **details):
    return {
        "valid": valid,
        "score": float(valid) if score is None else score,
        "message": message,
        "details": details,
    }


def path_problem(relative, suffix=None):
    path = Path(relative)
    if not relative.strip() or path.is_absolute() or ".." in path.parts:
        return f"{relative!r} must stay inside the plugin workspace"
    if suffix and path.suffix != suffix:
        return f"{relative!r} must be a {suffix} file"
    return None


def bounds_problem(precision, endpoint):
    if not MIN_PRECISION <= precision <= MAX_PRECISION:
        return f"precision must be between {MIN_PRECISION} and {MAX_PRECISION}"
    if endpoint and not endpoint.startswith(ENDPOINT_PREFIX):
        return f"endpoint must be empty or start with {ENDPOINT_PREFIX}"
    return None


def read_log(workspace, relative):
    """The log's rows as dicts, or a string saying why it cannot be read."""
    target = Path(workspace) / relative
    if not target.is_file():
        return f"{relative} is not in the workspace"
    lines = target.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].split(",") != COLUMNS:
        return f"{relative} does not start with the header {','.join(COLUMNS)}"
    rows = []
    for number, line in enumerate(lines[1:], start=2):
        cells = line.split(",")
        if len(cells) != len(COLUMNS):
            return f"{relative} line {number} does not have {len(COLUMNS)} columns"
        rows.append(dict(zip(COLUMNS, cells)))
    return rows


def selected(rows, field, status_class, endpoint):
    """The ``field`` value of every row in ``status_class`` (a contract StatusClass) and ``endpoint`` ("" for all)."""
    return [
        row[field.value]
        for row in rows
        if (status_class.value == "any" or row["status"][:1] == status_class.value[0])
        and (not endpoint or row["endpoint"] == endpoint)
    ]


def hll_registers(values, precision):
    """The HyperLogLog registers for ``values``: blake2b 64-bit hash, top ``precision`` bits pick the register."""
    width = 64 - precision
    registers = [0] * (2**precision)
    for value in values:
        hashed = int.from_bytes(hashlib.blake2b(value.encode("utf-8"), digest_size=8).digest(), "big")
        index = hashed >> width
        rank = width - (hashed & (2**width - 1)).bit_length() + 1
        registers[index] = max(registers[index], rank)
    return registers


def hll_estimate(registers):
    """The rounded estimate, with linear counting when the raw estimate is at most 2.5 m and a register is empty."""
    m = len(registers)
    if m == 16:
        alpha = 0.673
    elif m == 32:
        alpha = 0.697
    elif m == 64:
        alpha = 0.709
    else:
        alpha = 0.7213 / (1 + 1.079 / m)
    raw = alpha * m * m / sum(2.0**-rank for rank in registers)
    zeros = registers.count(0)
    if raw <= 2.5 * m and zeros > 0:
        raw = m * math.log(m / zeros)
    return round(raw)


def standard_error(precision):
    return round(1.04 / math.sqrt(2**precision), 6)


def error_bound(exact, precision):
    """How far an estimate may sit from the exact count before it is not credible: 4 standard errors, plus 2."""
    return 4 * standard_error(precision) * exact + 2
