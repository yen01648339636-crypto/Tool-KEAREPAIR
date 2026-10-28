"""LangChain request callbacks connected to the same per-case request journal."""

import time
from langchain_core.callbacks import BaseCallbackHandler
from utils.telemetry import (
    begin_call,
    finish_call,
    current_recorder,
    json_value,
    measure,
)


class RequestCallback(BaseCallbackHandler):
    def __init__(self, model, stage_name):
        self.model, self.stage_name = model, stage_name
        self.recorder = current_recorder()
        self.pending = {}

    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
        name = (
            getattr(self.model, "model_name", None)
            or getattr(self.model, "model", None)
            or (serialized or {}).get("name")
            or "unknown"
        )
        kind = type(self.model).__module__
        if getattr(self.model, "_llm_type", None) == "diagnostic-mock":
            provider = "mock"
        else:
            provider = next(
                (
                    name
                    for module, name in (
                        ("openai", "openai"),
                        ("anthropic", "anthropic"),
                        ("google", "gemini"),
                    )
                    if module in kind
                ),
                "unknown",
            )
        parameters = dict(
            invocation_params=json_value(kwargs.get("invocation_params", {})),
            messages=[[json_value(message) for message in batch] for batch in messages],
        )
        record = begin_call(
            str(name),
            provider,
            parameters,
            stage_name=self.stage_name,
            recorder=self.recorder,
            simulation=provider == "mock",
        )
        self.pending[str(run_id)] = record, time.monotonic()

    def on_llm_end(self, response, *, run_id, **kwargs):
        pair = self.pending.pop(str(run_id), None)
        if not pair:
            return
        record, started = pair
        generation = (
            response.generations[0][0]
            if response.generations and response.generations[0]
            else None
        )
        message = getattr(generation, "message", None)
        usage = getattr(message, "usage_metadata", None) or (
            response.llm_output or {}
        ).get("token_usage")
        metadata = getattr(message, "response_metadata", {}) or {}
        if record["simulation"]:
            usage = None
        finish_call(
            record,
            started,
            raw_usage=usage,
            cost=metadata.get("cost"),
            response=json_value(message),
            response_metadata=metadata,
            unified_usage=bool(getattr(message, "usage_metadata", None)),
            recorder=self.recorder,
        )

    def on_llm_error(self, error, *, run_id, **kwargs):
        pair = self.pending.pop(str(run_id), None)
        if pair:
            finish_call(pair[0], pair[1], error=error, recorder=self.recorder)


def chat_call(runnable, messages, stage_name, *, model):
    from utils.runtime_progress import progress_activity
    callback = RequestCallback(model, stage_name)
    label = {"diagnosis": "Diagnosis agent: requesting source analysis", "diagnosis_report": "Diagnosis agent: composing the report"}.get(stage_name, "Model request: " + stage_name)
    with measure("generation", generation_stage=stage_name), progress_activity(label, kind="model"):
        return runnable.invoke(messages, config={"callbacks": [callback]})
