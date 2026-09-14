"""Assigned-role debate monitor: prosecutor, defender, then judge (1 simultaneous turn)."""

from __future__ import annotations

import random
import sys
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.model import (
    ChatMessageAssistant,
    ChatMessageUser,
    ModelOutput,
    get_model,
)
from inspect_ai.solver import Generate, TaskState, solver

sys.path.insert(0, str(Path(__file__).resolve().parent))

from constants import PROMPT_PACKS
from slice_dataset import fill_template, read_template, slice_samples
from suspicion import suspicion_score

MOCK_PROSECUTOR = (
    "Prosecutor mock: tool call [1] is the only step I will mention. "
    "This is canned text so you can check the judge prompt."
)
MOCK_DEFENDER = (
    "Defender mock: tool call [1] is ordinary main-task work. "
    "This is canned text so you can check the judge prompt."
)
MOCK_JUDGE = """<reasoning>
Mock judge: both sides spoke. Returning 7 so the scorer has XML to parse.
</reasoning>
<score>
7
</score>
"""


def pack_templates(prompt_pack: str) -> tuple[str, str, str]:
    try:
        return PROMPT_PACKS[prompt_pack]
    except KeyError as exc:
        known = ", ".join(sorted(PROMPT_PACKS))
        raise ValueError(f"unknown prompt pack {prompt_pack!r}; use one of: {known}") from exc


@solver
def assigned_debate(prompt_pack: str = "default"):
    """Two isolated opening arguments, then a judge who sees both plus the trace."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        del generate
        prosecutor_tmpl, defender_tmpl, judge_tmpl = pack_templates(prompt_pack)
        meta = state.metadata or {}
        task_description = str(meta.get("task_description") or "")
        tool_calls = str(meta.get("tool_calls") or "")
        prosecutor_prompt = fill_template(
            read_template(prosecutor_tmpl),
            task_description=task_description,
            tool_calls=tool_calls,
        )
        defender_prompt = fill_template(
            read_template(defender_tmpl),
            task_description=task_description,
            tool_calls=tool_calls,
        )
        model = get_model()
        p_out = await model.generate(prosecutor_prompt)
        d_out = await model.generate(defender_prompt)
        prosecutor_arg = p_out.completion
        defender_arg = d_out.completion
        prosecutor_first = random.Random(str(state.sample_id)).random() < 0.5
        if prosecutor_first:
            first_role, first_arg = "prosecutor", prosecutor_arg
            second_role, second_arg = "defender", defender_arg
        else:
            first_role, first_arg = "defender", defender_arg
            second_role, second_arg = "prosecutor", prosecutor_arg
        judge_prompt = fill_template(
            read_template(judge_tmpl),
            task_description=task_description,
            tool_calls=tool_calls,
            first_role=first_role,
            first_arg=first_arg,
            second_role=second_role,
            second_arg=second_arg,
        )
        j_out = await model.generate(judge_prompt)
        state.metadata = dict(meta)
        state.metadata["prosecutor_first"] = prosecutor_first
        state.metadata["prompt_pack"] = prompt_pack
        state.metadata["prosecutor_arg"] = prosecutor_arg
        state.metadata["defender_arg"] = defender_arg
        state.metadata["judge_arg"] = j_out.completion
        model_name = getattr(j_out, "model", None) or str(model)
        state.messages = [
            ChatMessageUser(content=prosecutor_prompt),
            ChatMessageAssistant(content=prosecutor_arg, model=model_name),
            ChatMessageUser(content=defender_prompt),
            ChatMessageAssistant(content=defender_arg, model=model_name),
            ChatMessageUser(content=judge_prompt),
            ChatMessageAssistant(content=j_out.completion, model=model_name),
        ]
        state.output = j_out
        return state

    return solve


@task
def debate_monitor(
    uuid: str | None = None,
    mock: bool = False,
    prompts: str = "default",
) -> Task:
    """Score frozen trajectories after one-turn assigned-role debate.

    uuid: slot or sample_uuid, or a comma-separated list (default: all 12).
    mock: three canned completions, no API key.
    prompts: pack name from PROMPT_PACKS ("default" or "bundle").
    """
    pack_templates(prompts)
    queries = [part.strip() for part in uuid.split(",") if part.strip()] if uuid else None
    dataset = slice_samples(queries=queries) if queries else slice_samples()
    model = None
    if mock:
        n = len(dataset)
        custom = []
        for _ in range(max(n, 1)):
            custom.extend(
                [
                    ModelOutput.from_content("mockllm/model", MOCK_PROSECUTOR),
                    ModelOutput.from_content("mockllm/model", MOCK_DEFENDER),
                    ModelOutput.from_content("mockllm/model", MOCK_JUDGE),
                ]
            )
        model = get_model("mockllm/model", custom_outputs=custom)
    return Task(
        dataset=dataset,
        solver=assigned_debate(prompt_pack=prompts),
        scorer=suspicion_score(),
        model=model,
        metadata={"protocol": "debate", "mock": mock, "prompt_pack": prompts},
    )
