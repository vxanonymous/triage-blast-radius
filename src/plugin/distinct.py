"""count_distinct: one HyperLogLog pass over an access log column, in 2^precision registers."""

import csv
import hashlib
import math
from pathlib import Path

from contract import CountInput, CountOutput, StatusClass
from plugin.traffic import COLUMNS

MIN_PRECISION, MAX_PRECISION = 4, 16
ENDPOINT_PREFIX = "/api/"


def check_bounds(precision: int, endpoint: str) -> None:
    if not MIN_PRECISION <= precision <= MAX_PRECISION:
        raise ValueError(f"precision must be between {MIN_PRECISION} and {MAX_PRECISION}, got {precision}")
    if endpoint and not endpoint.startswith(ENDPOINT_PREFIX):
        raise ValueError(f"endpoint must be empty or start with {ENDPOINT_PREFIX}, got {endpoint!r}")


def read_log(workspace: Path, file: str) -> list[dict[str, str]]:
    path = Path(file)
    if path.is_absolute() or ".." in path.parts or path.suffix != ".csv":
        raise ValueError(f"file {file!r} must be a .csv inside the plugin workspace")
    target = workspace / path
    if not target.is_file():
        raise FileNotFoundError(f"{file} is not in the workspace: generate it with generate_traffic first")
    with target.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != COLUMNS:
            raise ValueError(f"{file} does not have the access log columns {','.join(COLUMNS)}")
        return list(reader)


def matches(row: dict[str, str], wanted: StatusClass, endpoint: str) -> bool:
    in_class = wanted is StatusClass.ANY or row["status"][:1] == wanted.value[0]
    return in_class and (not endpoint or row["endpoint"] == endpoint)


def hash64(value: str) -> int:
    return int.from_bytes(hashlib.blake2b(value.encode("utf-8"), digest_size=8).digest(), "big")


def registers_of(values: list[str], precision: int) -> list[int]:
    """Each register's highest rank: 1 + the leading zeros of the hash bits left after the index."""
    width = 64 - precision
    registers = [0] * (1 << precision)
    for value in values:
        hashed = hash64(value)
        index, rest = hashed >> width, hashed & ((1 << width) - 1)
        registers[index] = max(registers[index], width - rest.bit_length() + 1)
    return registers


def alpha(m: int) -> float:
    return {16: 0.673, 32: 0.697, 64: 0.709}.get(m, 0.7213 / (1 + 1.079 / m))


def estimate_of(registers: list[int]) -> int:
    m = len(registers)
    raw = alpha(m) * m * m / sum(2.0**-rank for rank in registers)
    zeros = registers.count(0)
    if raw <= 2.5 * m and zeros > 0:
        raw = m * math.log(m / zeros)
    return round(raw)


def count_distinct(given: CountInput, workspace: Path) -> CountOutput:
    check_bounds(given.precision, given.endpoint)
    stream = [
        row[given.field.value]
        for row in read_log(workspace, given.file)
        if matches(row, given.status_class, given.endpoint)
    ]
    registers = registers_of(stream, given.precision)
    return CountOutput(
        file=given.file,
        field=given.field,
        status_class=given.status_class,
        endpoint=given.endpoint,
        precision=given.precision,
        rows_counted=len(stream),
        registers=len(registers),
        nonzero_registers=sum(1 for rank in registers if rank),
        estimate=estimate_of(registers),
        standard_error=round(1.04 / math.sqrt(len(registers)), 6),
    )
