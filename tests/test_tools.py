import math
from pathlib import Path

import pytest

from contract import CountInput, Field, GenerateInput, StatusClass
from plugin import count_distinct, generate_traffic
from plugin.distinct import estimate_of, registers_of

HEADER = "ts,client_ip,user_id,endpoint,status,latency_ms\n"


def test_the_same_seed_gives_the_same_bytes(tmp_path: Path) -> None:
    first = generate_traffic(GenerateInput(seed=7, requests=2000, destination="traffic"), tmp_path)
    data = (tmp_path / first.file).read_bytes()
    second = generate_traffic(GenerateInput(seed=7, requests=2000, destination="traffic"), tmp_path)
    assert first == second and (tmp_path / second.file).read_bytes() == data
    assert first.file == "traffic/traffic-7-2000.csv"
    other = generate_traffic(GenerateInput(seed=8, requests=2000, destination="traffic"), tmp_path)
    assert other.sha256 != first.sha256


@pytest.mark.parametrize(
    ("requests", "destination"),
    [(999, "traffic"), (200_001, "traffic"), (2000, "../out"), (2000, "/tmp/x"), (2000, " ")],
)
def test_refuses_bad_generate_inputs(tmp_path: Path, requests: int, destination: str) -> None:
    with pytest.raises(ValueError):
        generate_traffic(GenerateInput(seed=1, requests=requests, destination=destination), tmp_path)


def count(file: str, endpoint: str = "", precision: int = 12, status_class=StatusClass.SERVER_ERROR) -> CountInput:
    return CountInput(file=file, field=Field.USER_ID, status_class=status_class, endpoint=endpoint, precision=precision)


def test_hyperloglog_stays_close_to_the_exact_count() -> None:
    for distinct in (0, 1, 10, 500, 5000, 50_000):
        values = [f"v{index}" for index in range(distinct)] * 2
        for precision in (4, 10, 12, 16):
            estimate = estimate_of(registers_of(values, precision))
            error = 1.04 / math.sqrt(2**precision)
            assert abs(estimate - distinct) <= 4 * error * distinct + 2, (distinct, precision, estimate)


def test_an_empty_sketch_estimates_zero() -> None:
    assert estimate_of(registers_of([], 4)) == 0


def test_estimates_the_planted_blast_radius(tmp_path: Path) -> None:
    log = generate_traffic(GenerateInput(seed=2, requests=20_000, destination="traffic"), tmp_path)
    found = {
        endpoint: count_distinct(count(log.file, endpoint), tmp_path).estimate
        for endpoint in ("/api/search", "/api/products", "/api/cart", "/api/login")
    }
    assert max(found, key=found.get) == "/api/cart"
    total = count_distinct(count(log.file), tmp_path)
    assert total.registers == 4096 and total.standard_error == 0.01625 and total.estimate > found["/api/cart"]
    assert total.nonzero_registers <= total.rows_counted


@pytest.mark.parametrize(("precision", "endpoint"), [(3, ""), (17, ""), (12, "api/cart"), (12, "/cart")])
def test_refuses_bad_bounds(tmp_path: Path, precision: int, endpoint: str) -> None:
    log = generate_traffic(GenerateInput(seed=1, requests=1000, destination="traffic"), tmp_path)
    with pytest.raises(ValueError):
        count_distinct(count(log.file, endpoint, precision), tmp_path)


def test_refuses_a_missing_or_foreign_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        count_distinct(count("traffic/none.csv"), tmp_path)
    (tmp_path / "other.csv").write_text("a,b\n1,2\n")
    with pytest.raises(ValueError):
        count_distinct(count("other.csv"), tmp_path)
    with pytest.raises(ValueError):
        count_distinct(count("../outside.csv"), tmp_path)


def test_counts_only_the_endpoint_and_class_asked(tmp_path: Path) -> None:
    rows = ["2026-10-31T12:00:00Z,10.0.0.1,u0001,/api/a,500,5", "2026-10-31T12:00:01Z,10.0.0.2,u0002,/api/b,503,5"]
    rows += ["2026-10-31T12:00:02Z,10.0.0.3,u0003,/api/a,200,5"]
    (tmp_path / "log.csv").write_text(HEADER + "\n".join(rows) + "\n")
    assert count_distinct(count("log.csv", "/api/a"), tmp_path).estimate == 1
    assert count_distinct(count("log.csv"), tmp_path).estimate == 2
    assert count_distinct(count("log.csv", "/api/a", 4, StatusClass.ANY), tmp_path).rows_counted == 2
    assert count_distinct(count("log.csv", "/api/none"), tmp_path).estimate == 0
