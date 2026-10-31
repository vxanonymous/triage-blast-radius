"""generate_traffic: a seeded web access log with one planted incident, written into the workspace."""

import hashlib
import random
from datetime import UTC, datetime
from pathlib import Path

from contract import GenerateInput, GenerateOutput

COLUMNS = ["ts", "client_ip", "user_id", "endpoint", "status", "latency_ms"]
MIN_REQUESTS, MAX_REQUESTS = 1000, 200_000
START = 1_793_448_000  # 2026-10-31T12:00:00Z, so every file shares one clock
# Endpoints and their share of normal traffic.
ENDPOINTS = {
    "/api/search": 30,
    "/api/products": 20,
    "/api/cart": 14,
    "/api/login": 8,
    "/api/checkout": 7,
    "/api/profile": 7,
    "/api/reviews": 7,
    "/api/health": 7,
}
# The endpoints the incident may hit: the seed picks one.
FAULTY = ["/api/cart", "/api/login", "/api/checkout", "/api/profile", "/api/reviews"]


def safe_folder(destination: str) -> Path:
    path = Path(destination)
    if not destination.strip() or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"destination {destination!r} must be a folder inside the plugin workspace")
    return path


def traffic_name(seed: int, requests: int) -> str:
    return f"traffic-{seed}-{requests}.csv"


def _timestamp(second: int) -> str:
    return datetime.fromtimestamp(START + second, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def rows(seed: int, requests: int) -> list[list[str]]:
    rng = random.Random(seed)
    faulty = rng.choice(FAULTY)
    scraper = f"10.9.{rng.randrange(256)}.{rng.randrange(256)}"
    ips = [f"10.{rng.randrange(8)}.{rng.randrange(256)}.{rng.randrange(256)}" for _ in range(400)]
    names, weights = list(ENDPOINTS), list(ENDPOINTS.values())
    # The incident covers the middle third of the log.
    start, end = requests // 3, 2 * requests // 3
    lines = []
    for index in range(requests):
        endpoint = rng.choices(names, weights)[0]
        client = scraper if rng.random() < 0.12 else rng.choice(ips)
        user = f"u{rng.randrange(1, 5001):04d}"
        roll = rng.random()
        if start <= index < end and endpoint == faulty and roll < 0.6:
            status, latency = rng.choice([500, 502, 503, 504]), rng.randint(900, 5000)
        elif roll < 0.01:
            status, latency = rng.choice([500, 503]), rng.randint(200, 2000)
        elif roll < 0.06:
            status, latency = rng.choice([400, 401, 403, 404, 429]), rng.randint(5, 80)
        else:
            status, latency = rng.choice([200, 200, 200, 201, 204]), rng.randint(10, 400)
        lines.append([_timestamp(index * 86_400 // requests), client, user, endpoint, str(status), str(latency)])
    return lines


def generate_traffic(given: GenerateInput, workspace: Path) -> GenerateOutput:
    if not MIN_REQUESTS <= given.requests <= MAX_REQUESTS:
        raise ValueError(f"requests must be between {MIN_REQUESTS} and {MAX_REQUESTS}, got {given.requests}")
    folder = safe_folder(given.destination)
    relative = folder / traffic_name(given.seed, given.requests)
    text = "\n".join(",".join(line) for line in [COLUMNS, *rows(given.seed, given.requests)]) + "\n"
    data = text.encode("utf-8")
    target = workspace / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return GenerateOutput(
        file=relative.as_posix(),
        requests=given.requests,
        columns=list(COLUMNS),
        sha256=hashlib.sha256(data).hexdigest(),
    )
