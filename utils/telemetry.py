"""Append-only request attempts, measured stage timings, and explicit unknown costs."""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import date, datetime, timezone
import json
import math
import os
from pathlib import Path
import threading
import time
from uuid import uuid4

from utils.experiment_manifest import sanitize_config
from utils.llm_errors import LLMOutputValidationError
from utils.schemas import ContractError

_ACTIVE = ContextVar("run_recorder", default=None)
_STAGE = ContextVar("call_stage", default="unspecified")
_CANDIDATE = ContextVar("candidate_id", default=None)
_CALL_CONTEXT = ContextVar("request_context", default={})
_LOCK = threading.RLock()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def json_value(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    elif hasattr(value, "__dict__") and type(value).__module__ == "types":
        value = vars(value)
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_value(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    return str(value)


def append_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, path.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(json_value(value), ensure_ascii=False, allow_nan=False) + "\n"
        )
        stream.flush()


def number(value):
    return (
        value
        if type(value) in (int, float) and math.isfinite(value) and value >= 0
        else None
    )


def normalize_usage(raw, provider, *, unified=False):
    raw = json_value(raw) or {}
    if not isinstance(raw, dict):
        raw = {}

    def get(*names):
        return next(
            (number(raw[name]) for name in names if number(raw.get(name)) is not None),
            None,
        )

    input_tokens = get("input_tokens", "prompt_tokens", "prompt_token_count")
    output_tokens = get("output_tokens", "completion_tokens", "candidates_token_count")
    details = raw.get("input_token_details") or raw.get("prompt_tokens_details") or {}
    cached = get("cache_read_input_tokens", "cached_content_token_count")
    if cached is None:
        cached = number(details.get("cache_read", details.get("cached_tokens")))
    cache_write = get("cache_creation_input_tokens")
    reasoning = get("thoughts_token_count")
    if reasoning is None:
        reasoning = number(
            (
                raw.get("output_token_details")
                or raw.get("completion_tokens_details")
                or {}
            ).get("reasoning")
        )
        if reasoning is None:
            reasoning = number(
                (raw.get("completion_tokens_details") or {}).get("reasoning_tokens")
            )
    # Gemini reports visible output and thoughts separately; never silently drop thoughts.
    if (
        provider == "gemini"
        and "candidates_token_count" in raw
        and output_tokens is not None
    ):
        output_tokens = output_tokens + reasoning if reasoning is not None else None
    if unified:
        cache_write = number(details.get("cache_creation"))
    exclusive = provider == "anthropic" and not unified
    total_input = input_tokens
    if exclusive:
        total_input = (
            input_tokens + cached + cache_write
            if all(value is not None for value in (input_tokens, cached, cache_write))
            else None
        )
    return dict(
        input_tokens=input_tokens,
        total_input_tokens=total_input,
        output_tokens=output_tokens,
        total_tokens=get("total_tokens", "total_token_count"),
        cached_input_tokens=cached,
        cache_write_input_tokens=cache_write,
        reasoning_tokens=reasoning,
        input_semantics=("exclusive_of_cache" if exclusive else "inclusive"),
        raw=raw,
    )


def reported_cost(value):
    value = json_value(value)
    if (
        not isinstance(value, dict)
        or number(value.get("amount")) is None
        or not isinstance(value.get("currency"), str)
        or not value["currency"].strip()
    ):
        return None
    return dict(
        amount=float(value["amount"]),
        currency=value["currency"].upper(),
        source="provider",
    )


def load_pricing(path):
    if path is None:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or set(data) != {"prices"}
        or not isinstance(data["prices"], list)
    ):
        raise ValueError("Pricing snapshot must contain a prices list")
    keys = set()
    for item in data["prices"]:
        required = {
            "provider",
            "model",
            "currency",
            "as_of",
            "source",
            "input_per_million",
            "output_per_million",
        }
        if (
            not isinstance(item, dict)
            or not required <= set(item)
            or set(item)
            - required
            - {"cached_input_per_million", "cache_write_per_million"}
        ):
            raise ValueError("Invalid price entry")
        date.fromisoformat(item["as_of"])
        if any(
            not isinstance(item[key], str) or not item[key].strip()
            for key in ("provider", "model", "currency", "source")
        ):
            raise ValueError(
                "Price entries require exact model/provider, currency and source"
            )
        if any(
            number(item[key]) is None
            for key in set(item)
            & {
                "input_per_million",
                "output_per_million",
                "cached_input_per_million",
                "cache_write_per_million",
            }
        ):
            raise ValueError(
                "Pricing rates must be finite, nonnegative actual supplied values"
            )
        key = (item["provider"], item["model"])
        if key in keys:
            raise ValueError("Ambiguous pricing entry for model/provider")
        keys.add(key)
    return data


def estimate_cost(record, snapshot):
    if not snapshot or record.get("simulation"):
        return None
    response = record.get("response_metadata") or {}
    resolved_model = (
        response.get("model")
        or response.get("model_name")
        or response.get("model_version")
        or record["model"]
    )
    entry = next(
        (
            item
            for item in snapshot["prices"]
            if item["provider"] == record["provider"]
            and item["model"] == resolved_model
        ),
        None,
    )
    usage = record["usage"]
    if not entry or usage["input_tokens"] is None or usage["output_tokens"] is None:
        return None
    base = usage["input_tokens"]
    cached, write = usage["cached_input_tokens"], usage["cache_write_input_tokens"]
    if usage["input_semantics"] == "exclusive_of_cache":
        if (
            cached is None
            or write is None
            or "cached_input_per_million" not in entry
            or "cache_write_per_million" not in entry
        ):
            return None
        amount = (
            base * entry["input_per_million"]
            + cached * entry["cached_input_per_million"]
            + write * entry["cache_write_per_million"]
        )
    else:
        cached_rate = entry.get("cached_input_per_million")
        if (
            cached is None
            and cached_rate != entry["input_per_million"]
            or cached
            and cached_rate is None
        ):
            return None
        cached = 0 if cached is None else cached
        write = write if record["provider"] == "anthropic" else 0
        if write is None or write and "cache_write_per_million" not in entry:
            return None
        if cached + write > base:
            return None
        amount = (
            (base - cached - write) * entry["input_per_million"]
            + cached * (cached_rate or 0)
            + write * entry.get("cache_write_per_million", 0)
        )
    amount += usage["output_tokens"] * entry["output_per_million"]
    return dict(
        amount=amount / 1_000_000,
        currency=entry["currency"].upper(),
        source="price_snapshot_estimate",
        priced_model=resolved_model,
        price_as_of=entry["as_of"],
        price_source=entry["source"],
    )


class Recorder:
    def __init__(
        self, directory, *, phase="online", case_id=None, pricing=None, run_id=None
    ):
        self.directory = Path(directory)
        self.phase, self.case_id, self.pricing = phase, case_id, pricing
        self.run_id = run_id or uuid4().hex
        self.directory.mkdir(parents=True, exist_ok=True)
        self.attempt_offset = max(
            (
                int(path.name)
                for path in (self.directory / "attempts").glob("*")
                if path.name.isdigit()
            ),
            default=0,
        )

    def emit(self, filename, value):
        append_json(
            self.directory / filename,
            dict(phase=self.phase, case_id=self.case_id, run_id=self.run_id, **value),
        )

    @contextmanager
    def activate(self):
        token = _ACTIVE.set(self)
        try:
            yield self
        finally:
            _ACTIVE.reset(token)


def current_recorder():
    return _ACTIVE.get()


@contextmanager
def request_context(**metadata):
    token = _CALL_CONTEXT.set({**_CALL_CONTEXT.get(), **metadata})
    try:
        yield
    finally:
        _CALL_CONTEXT.reset(token)


@contextmanager
def stage(name, *, candidate_id=None):
    token = _STAGE.set(name)
    candidate_token = _CANDIDATE.set(candidate_id) if candidate_id is not None else None
    try:
        yield
    finally:
        _STAGE.reset(token)
        if candidate_token is not None:
            _CANDIDATE.reset(candidate_token)


@contextmanager
def measure(name, *, started_monotonic=None, started_at=None, **metadata):
    from utils.execution_control import wait_if_paused, paused_seconds
    wait_if_paused()
    paused_before = paused_seconds()
    started, stamp, error = (
        started_monotonic if started_monotonic is not None else time.monotonic(),
        started_at or utc_now(),
        None,
    )
    recorder = current_recorder()
    try:
        yield
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if recorder:
            recorder.emit(
                "timings.jsonl",
                dict(
                    stage=name,
                    candidate_id=_CANDIDATE.get(),
                    started_at=stamp,
                    duration_seconds=max(0.0, time.monotonic() - started - (paused_seconds() - paused_before)),
                    paused_seconds=paused_seconds() - paused_before,
                    error=error,
                    **metadata,
                ),
            )


def begin_call(
    model,
    provider,
    parameters,
    *,
    stage_name=None,
    recorder=None,
    simulation=False,
    retry_index=0,
    request_group_id=None,
):
    from utils.execution_control import wait_if_paused
    wait_if_paused()
    recorder = recorder or current_recorder()
    record = dict(
        call_id=uuid4().hex,
        event="started",
        stage=stage_name or _STAGE.get(),
        candidate_id=_CANDIDATE.get(),
        model=model or "unknown",
        provider=provider or "unknown",
        parameters=sanitize_config(json_value(parameters)),
        started_at=utc_now(),
        duration_seconds=None,
        status="incomplete",
        retry_index=retry_index,
        request_group_id=request_group_id,
        simulation=simulation,
        usage=normalize_usage(None, provider),
        provider_cost=None,
        estimated_cost=None,
    )
    record["context"] = json_value(_CALL_CONTEXT.get())
    if recorder:
        recorder.emit("llm_calls.jsonl", record)
    return record


def finish_call(
    record,
    started,
    *,
    raw_usage=None,
    cost=None,
    error=None,
    recorder=None,
    response=None,
    response_metadata=None,
    unified_usage=False,
):
    recorder = recorder or current_recorder()
    record.update(
        event="finished",
        duration_seconds=time.monotonic() - started,
        status="failed" if error else "completed",
        error=str(error) if error else None,
        response=json_value(response),
        response_metadata=sanitize_config(json_value(response_metadata)),
        usage=normalize_usage(raw_usage, record["provider"], unified=unified_usage),
        provider_cost=reported_cost(cost),
    )
    if recorder:
        record["estimated_cost"] = estimate_cost(record, recorder.pricing)
        recorder.emit("llm_calls.jsonl", record)
    return record


def text_call(llm, prompt, stage_name, *, response_validator=None, **options):
    """Custom/local text backends remain observable without inventing SDK usage."""
    from utils.runtime_progress import progress_activity
    with stage(stage_name), measure("generation", generation_stage=stage_name), progress_activity("Model request: " + stage_name, kind="model"):
        if getattr(llm, "validates_responses", False) and response_validator is not None:
            return llm.generate(prompt, response_validator=response_validator, **options)
        if getattr(llm, "records_requests", False) and response_validator is None:
            return llm.generate(prompt, **options)
        max_attempts = max(1, int(os.getenv("LLM_MAX_RETRIES", "3"))) if response_validator else 1
        group_id = uuid4().hex if response_validator else None
        for attempt in range(max_attempts):
            record = begin_call(
                getattr(llm, "model_name", None),
                getattr(llm, "provider", None),
                dict(prompt=prompt, **options),
                simulation=getattr(llm, "provider", None) == "mock",
                retry_index=attempt,
                request_group_id=group_id,
            )
            started = time.monotonic()
            response = None
            validating_response = False
            try:
                response = llm.generate(prompt, **options)
                if response_validator is not None:
                    validating_response = True
                    response_validator(response)
                    validating_response = False
            except BaseException as exc:
                finish_call(record, started, error=exc, response=response)
                if validating_response and isinstance(exc, ContractError):
                    if attempt + 1 < max_attempts:
                        continue
                    raise LLMOutputValidationError(
                        f"LLM output validation failed after {max_attempts} attempts: {exc}",
                        attempts=max_attempts,
                    ) from exc
                raise
            finish_call(record, started, response=response)
            return response


def read_jsonl(path):
    if not Path(path).exists():
        return []
    records = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("Expected an object")
            records.append(value)
        except ValueError:
            records.append(
                {
                    "event": "corrupt_record",
                    "status": "incomplete",
                    "count_unknown": True,
                    "error": "Unfinished or corrupt JSONL line",
                }
            )
    return records


def request_records(path):
    records = {}
    for index, event in enumerate(read_jsonl(path)):
        records[event.get("call_id", f"corrupt-{index}")] = event
    return list(records.values())


def accounted_requests(path, expected_count=None, *, evidence_of_calls=False):
    records = request_records(path)
    if type(expected_count) is int and expected_count > len(records):
        records.extend(
            dict(
                call_id=f"missing-{index}",
                status="incomplete",
                stage="unknown",
                error="Request record missing; count preserved from result metadata",
            )
            for index in range(expected_count - len(records))
        )
    elif expected_count is None and not Path(path).exists() and evidence_of_calls:
        records.append(
            dict(
                status="incomplete",
                stage="unknown",
                count_unknown=True,
                error="Request journal missing; actual request count unknown",
            )
        )
    return records
