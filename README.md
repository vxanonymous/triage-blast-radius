# Triage Blast Radius

A `nanoagent.plugin/v0001` plugin for incident triage. It writes a seeded web
access log with one planted outage, then estimates how many distinct users,
client IPs or endpoints a slice of the log touched, such as the users who got
a 5xx response from one endpoint. It uses a HyperLogLog sketch that keeps
`2^precision` small registers however many users there are, which is how a
triage agent can size an incident's blast radius in fixed memory.

## Tools

| Tool | Does | Code |
|---|---|---|
| `generate_traffic` | Writes the access log for a seed and request count to `<destination>/traffic-<seed>-<requests>.csv` and returns its path, row count, columns and SHA-256 | `src/plugin/traffic.py` |
| `count_distinct` | One HyperLogLog pass over a column, restricted to a status class and an endpoint (`""` for all): the estimated distinct count and its standard error | `src/plugin/distinct.py` |

### Tasks

| Task | Does | Runner |
|---|---|---|
| `generate-traffic` | Generates a seeded access log | `tool`, with `generate_traffic` |
| `count-affected` | Estimates the distinct values of a column | `tool`, with `count_distinct` |
| `largest-blast-radius` | Finds the endpoint whose 5xx responses reached the most distinct users, and how many users got a 5xx in all | `agent`, with `generate_traffic` and `count_distinct` |

The log has the columns `ts,client_ip,user_id,endpoint,status,latency_ms`.
Its seed picks one endpoint that fails with 5xx responses 60% of the time
during the middle third of the log, and one scraper IP that sends about 12%
of all requests. Users are drawn from 5000 ids. The same seed and request
count always give the same bytes.

### The HyperLogLog, exactly

`count_distinct` and the verifier both compute this, so the estimate is one
fixed number for a given file and settings. With precision `p` and
`m = 2^p` registers, all starting at 0:

1. Hash each selected value: `h = int.from_bytes(hashlib.blake2b(value.encode("utf-8"), digest_size=8).digest(), "big")`, a 64-bit integer.
2. The register is `index = h >> (64 - p)`, the top `p` bits.
3. The rest is `w = h & ((1 << (64 - p)) - 1)`. Its rank is
   `(64 - p) - w.bit_length() + 1`, one more than its leading zeros, so
   `w == 0` has rank `64 - p + 1`.
4. The register keeps the largest rank it sees.
5. The raw estimate is `E = alpha_m * m^2 / sum(2^-M[j])`, with
   `alpha_16 = 0.673`, `alpha_32 = 0.697`, `alpha_64 = 0.709` and
   `alpha_m = 0.7213 / (1 + 1.079 / m)` for larger `m`.
6. If `E <= 2.5 * m` and `V > 0` registers are still 0, linear counting
   replaces it: `E = m * ln(m / V)`. A 64-bit hash needs no large-range
   correction.
7. `estimate = round(E)`, with Python's `round`.

`standard_error` is `1.04 / sqrt(m)` rounded to 6 places: 0.01625 at the
precision 12 the agent task uses.

## Layout

```text
.
├── nanoagent.yaml   # manifest (a slimconfig ManifestConfig): id, runtime, permissions, tools, tasks
├── contract.py      # each tool's and task's typed input and output: slimconfig Output classes
├── README.md
├── LICENSE
├── pyproject.toml
├── uv.lock
├── .gitignore
├── .env             # needed environment variable names (none here)
├── src/plugin/      # the MCP server (__main__.py, its IMPLEMENTATIONS table) and the tools
├── tests/
├── ui/              # outputs are drawn from their JSON Schema
├── product/         # the product page a catalog shows: product.yaml and icon.svg
└── verifier/        # deterministic verifier, one module per tool, and blast.py for largest-blast-radius
```

`verifier/` imports only the standard library and `contract`. It reads the
log back from the workspace, selects the rows again, rebuilds the HyperLogLog
with its own code and also counts the distinct values exactly, then checks:

- `generate_traffic`: the file is at `<destination>/traffic-<seed>-<requests>.csv`,
  its SHA-256 is the declared one, its header is the log's, and it holds
  exactly the requested rows.
- `count_distinct`: the echoed inputs match; `rows_counted`, `registers`,
  `nonzero_registers` and `standard_error` are exact; `estimate` equals the
  recomputed HyperLogLog estimate; and, as a sanity bound, it is within
  `4 * standard_error * exact + 2` of the exact distinct count.
- `largest-blast-radius`: the file is the seed's log, the endpoint has the
  most distinct users with a 5xx response by exact count (any of them on a
  tie), `affected_estimate` equals the precision 12 HyperLogLog of that
  endpoint's 5xx users, and `total_affected_estimate` equals the precision 12
  HyperLogLog of all 5xx users. The score is the share of these three checks
  that pass.

## Develop and run

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
```

NanoAgent passes the folder the plugin may write to as `NANOAGENT_WORKSPACE`.
Logs are written there; `count_distinct` reads a log by its path inside it.
