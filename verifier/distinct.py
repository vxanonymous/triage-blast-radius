"""count_distinct's checks: the HyperLogLog recomputed from the file, and the exact distinct count."""

from .checks import (
    bounds_problem,
    error_bound,
    hll_estimate,
    hll_registers,
    path_problem,
    read_log,
    result,
    selected,
    standard_error,
)


def verify_input(value):
    problem = path_problem(value.file, ".csv") or bounds_problem(value.precision, value.endpoint)
    if problem:
        return result(False, problem)
    return result(True, "input is valid")


def sketch_problems(input_value, output_value, rows):
    """Every way ``output_value`` differs from the HyperLogLog of ``rows``; empty when it matches."""
    stream = selected(rows, input_value.field, input_value.status_class, input_value.endpoint)
    registers = hll_registers(stream, input_value.precision)
    estimate = hll_estimate(registers)
    exact = len(set(stream))
    problems = []
    asked = (input_value.file, input_value.field, input_value.status_class, input_value.endpoint, input_value.precision)
    echoed = (
        output_value.file,
        output_value.field,
        output_value.status_class,
        output_value.endpoint,
        output_value.precision,
    )
    if echoed != asked:
        problems.append("file, field, status_class, endpoint or precision is not the one asked for")
    if output_value.rows_counted != len(stream):
        problems.append(f"rows_counted is {output_value.rows_counted}, but {len(stream)} rows match")
    if output_value.registers != len(registers):
        problems.append(f"registers is {output_value.registers}, not 2^precision = {len(registers)}")
    nonzero = sum(1 for rank in registers if rank)
    if output_value.nonzero_registers != nonzero:
        problems.append(f"nonzero_registers is {output_value.nonzero_registers}, not {nonzero}")
    if output_value.standard_error != standard_error(input_value.precision):
        problems.append(f"standard_error is {output_value.standard_error}, not 1.04/sqrt(m)")
    if output_value.estimate != estimate:
        problems.append(f"estimate is {output_value.estimate}, but the HyperLogLog gives {estimate}")
    if abs(output_value.estimate - exact) > error_bound(exact, input_value.precision):
        problems.append(f"estimate {output_value.estimate} is too far from the exact {exact} distinct values")
    return problems, estimate, exact


def verify_output(input_value, output_value, workspace):
    rows = read_log(workspace, input_value.file)
    if isinstance(rows, str):
        return result(False, rows)
    problems, estimate, exact = sketch_problems(input_value, output_value, rows)
    if problems:
        return result(False, problems[0], problems=problems, estimate=estimate, exact=exact)
    return result(True, f"estimate {estimate} matches the HyperLogLog; {exact} distinct exactly", exact=exact)
