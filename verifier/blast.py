"""largest-blast-radius's check: the submitted endpoint and estimates, against the seed's log recounted."""

from contract import Field, StatusClass

from .checks import hll_estimate, hll_registers, read_log, result, selected
from .generate import expected_file

PRECISION = 12


def verify_task(arguments, output, reference, workspace):
    """``output``: a contract BlastOutput for the log generated from ``arguments``' seed and request count."""
    expected = expected_file("traffic", arguments.seed, arguments.requests)
    if output.file != expected:
        return result(False, f"file is {output.file!r}, not the seed's log {expected}")
    rows = read_log(workspace, expected)
    if isinstance(rows, str):
        return result(False, rows)
    if len(rows) != arguments.requests:
        return result(False, f"{expected} holds {len(rows)} requests, not {arguments.requests}")
    affected = {}
    for row in rows:
        if row["status"][:1] == "5":
            affected.setdefault(row["endpoint"], set()).add(row["user_id"])
    if not affected:
        return result(False, "the log has no 5xx responses, so nobody was affected")
    most = max(len(users) for users in affected.values())
    widest = sorted(endpoint for endpoint, users in affected.items() if len(users) == most)
    endpoint_users = selected(rows, Field.USER_ID, StatusClass.SERVER_ERROR, output.endpoint)
    all_users = selected(rows, Field.USER_ID, StatusClass.SERVER_ERROR, "")
    endpoint_estimate = hll_estimate(hll_registers(endpoint_users, PRECISION))
    total_estimate = hll_estimate(hll_registers(all_users, PRECISION))
    checks = {
        "endpoint": output.endpoint in widest,
        "affected_estimate": output.affected_estimate == endpoint_estimate,
        "total_affected_estimate": output.total_affected_estimate == total_estimate,
    }
    failed = [name for name, passed in checks.items() if not passed]
    details = {
        "widest": widest,
        "endpoint_users": most,
        "total_users": len(set(all_users)),
        "total_estimate": total_estimate,
        "failed": failed,
    }
    score = (len(checks) - len(failed)) / len(checks)
    if failed:
        return result(False, f"wrong {', '.join(failed)}", score=score, **details)
    return result(True, f"{output.endpoint} sent 5xx responses to the most users ({most} exactly)", **details)
