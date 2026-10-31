"""The deterministic verifier: each tool's checks live in its own module, on contract instances."""

from contract import Task, Tool

from . import blast, distinct, generate

TOOLS = {
    Tool.GENERATE_TRAFFIC: generate,
    Tool.COUNT_DISTINCT: distinct,
}


def _tool_output(module):
    """A tool task's check: its output judged as its one tool's verify_output judges it."""
    return lambda arguments, output, reference, workspace: module.verify_output(arguments, output, workspace)


# task -> its output's check, verify_task(arguments, output, reference, workspace)
TASKS = {
    Task.GENERATE_TRAFFIC: _tool_output(generate),
    Task.COUNT_AFFECTED: _tool_output(distinct),
    Task.LARGEST_BLAST_RADIUS: blast.verify_task,
}


def verify_input(tool, value):
    return TOOLS[Tool(tool)].verify_input(value)


def verify_output(tool, input_value, output_value, workspace):
    return TOOLS[Tool(tool)].verify_output(input_value, output_value, workspace)


def verify_task(task, arguments, output, reference, workspace):
    return TASKS[Task(task)](arguments, output, reference, workspace)
