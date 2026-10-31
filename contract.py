"""Each tool's and task's typed input and output (see nanoagent.plugin.v0001.contract): declarations only."""

from dataclasses import dataclass
from enum import Enum
from typing import Annotated

from slimconfig import Output


class Tool(Enum):
    GENERATE_TRAFFIC = "generate_traffic"
    COUNT_DISTINCT = "count_distinct"


class Task(Enum):
    GENERATE_TRAFFIC = "generate-traffic"
    COUNT_AFFECTED = "count-affected"
    LARGEST_BLAST_RADIUS = "largest-blast-radius"


class Field(Enum):
    ENDPOINT = "endpoint"
    CLIENT_IP = "client_ip"
    USER_ID = "user_id"


class StatusClass(Enum):
    ANY = "any"
    SUCCESS = "2xx"
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"


SEED = "The scenario's seed: the same seed and request count always give the same file, byte for byte"
REQUESTS = "How many requests the access log holds, 1000 to 200000"
DESTINATION = "The folder relative to the plugin workspace the log is saved in, e.g. traffic"
FILE = "The access log, relative to the plugin workspace: <destination>/traffic-<seed>-<requests>.csv"
SHA256 = "The SHA-256 of the file's bytes, lowercase hex"
ENDPOINT = "Only rows of this endpoint are counted, e.g. /api/cart; an empty string counts every endpoint"
PRECISION = "p: the HyperLogLog keeps m = 2^p registers, 4 <= p <= 16"


@dataclass
class GenerateInput(Output):
    seed: Annotated[int, SEED]
    requests: Annotated[int, REQUESTS]
    destination: Annotated[str, DESTINATION]


@dataclass
class GenerateOutput(Output):
    file: Annotated[str, FILE]
    requests: Annotated[int, "How many request rows the file holds, after its header"]
    columns: Annotated[list[str], "The CSV header's column names, in order"]
    sha256: Annotated[str, SHA256]


@dataclass
class CountInput(Output):
    file: Annotated[str, "An access log CSV relative to the plugin workspace, e.g. traffic/traffic-7-20000.csv"]
    field: Annotated[Field, "The column whose distinct values are counted"]
    status_class: Annotated[StatusClass, "Only rows whose status is in this class are counted; any counts every row"]
    endpoint: Annotated[str, ENDPOINT]
    precision: Annotated[int, PRECISION]


@dataclass
class CountOutput(Output):
    file: Annotated[str, "The access log, as given"]
    field: Annotated[Field, "The column counted"]
    status_class: Annotated[StatusClass, "The status class counted"]
    endpoint: Annotated[str, "The endpoint filter, as given"]
    precision: Annotated[int, "p, as given"]
    rows_counted: Annotated[int, "How many rows matched the status class and endpoint filter"]
    registers: Annotated[int, "m = 2^p, how many registers the sketch kept"]
    nonzero_registers: Annotated[int, "How many registers hold a rank above zero after the pass"]
    estimate: Annotated[
        int,
        "The HyperLogLog estimate of the distinct values, with the blake2b 64-bit hash and the"
        " linear-counting small-range correction, rounded to the nearest integer",
    ]
    standard_error: Annotated[float, "The sketch's relative standard error, 1.04 / sqrt(m), rounded to 6 places"]


@dataclass
class BlastInput(Output):
    seed: Annotated[int, SEED]
    requests: Annotated[int, REQUESTS]


@dataclass
class BlastOutput(Output):
    file: Annotated[
        str, "The access log generated for the seed and request count, traffic/traffic-<seed>-<requests>.csv"
    ]
    endpoint: Annotated[str, "The endpoint whose 5xx responses reached the most distinct users"]
    affected_estimate: Annotated[
        int, "That endpoint's distinct users with a 5xx response, as count_distinct estimated it at precision 12"
    ]
    total_affected_estimate: Annotated[
        int, "Distinct users with a 5xx response on any endpoint, as count_distinct estimated it at precision 12"
    ]


TOOLS = {
    Tool.GENERATE_TRAFFIC: (GenerateInput, GenerateOutput),
    Tool.COUNT_DISTINCT: (CountInput, CountOutput),
}
TASKS = {
    Task.GENERATE_TRAFFIC: (GenerateInput, GenerateOutput),
    Task.COUNT_AFFECTED: (CountInput, CountOutput),
    Task.LARGEST_BLAST_RADIUS: (BlastInput, BlastOutput),
}
