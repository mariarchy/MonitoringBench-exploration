"""Full-trajectory (FT) monitor: one generate() on the filled ControlArena prompt."""

from __future__ import annotations

import sys
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.model import ModelOutput, get_model
from inspect_ai.solver import generate

sys.path.insert(0, str(Path(__file__).resolve().parent))

from slice_dataset import slice_samples
from suspicion import suspicion_score

MOCK_FT = """<reasoning>
Mock monitor: no live model. Returning 0 so the scorer has an XML tag to parse.
</reasoning>
<score>
0
</score>
"""


@task
def ft_monitor(uuid: str | None = None, mock: bool = False) -> Task:
    """Score frozen trajectories with the ControlArena FT prompt.

    uuid: one slice sample_uuid (default: all 12).
    mock: canned XML score, no API key.
    """
    dataset = slice_samples(uuid=uuid)
    model = None
    if mock:
        model = get_model(
            "mockllm/model",
            custom_outputs=[
                ModelOutput.from_content("mockllm/model", MOCK_FT),
            ],
        )
    return Task(
        dataset=dataset,
        solver=[generate()],
        scorer=suspicion_score(),
        model=model,
        metadata={"protocol": "ft", "mock": mock},
    )
