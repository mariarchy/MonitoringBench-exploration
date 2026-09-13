"""Smallest Inspect eval: one Sample, generate(), includes(), mockllm."""

from __future__ import annotations

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.model import ModelOutput, get_model
from inspect_ai.scorer import includes
from inspect_ai.solver import generate


@task
def hello() -> Task:
    return Task(
        dataset=[
            Sample(
                input="What is 2+2? Reply with just the number.",
                target="4",
            )
        ],
        solver=[generate()],
        scorer=includes(),
        model=get_model(
            "mockllm/model",
            custom_outputs=[
                ModelOutput.from_content("mockllm/model", "4"),
            ],
        ),
    )
