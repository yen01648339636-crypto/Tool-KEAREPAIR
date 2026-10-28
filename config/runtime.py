"""Load inherited configurations and resolve canonical runtime settings."""

from copy import deepcopy
import math
import re
from pathlib import Path


VIEWS = ("data_flow", "control_flow")
VARIANTS = (
    "full",
    "df_only",
    "cf_only",
    "no_retrieval",
    "no_diagnosis",
    "no_iteration",
)
SAMPLING_DEFAULTS = {
    # None inherits the shared LLM setting; each stage can override it explicitly.
    "extraction": (None, 1024),
    "blind": (None, 1024),
    "distillation": (None, 512),
    "query": (None, 1024),
    "diagnosis": (None, None),
    "diagnosis_report": (None, 4096),
    "initial_repair": (None, None),
    "refine_repair": (None, None),
}


class ConfigurationError(ValueError):
    """Configuration fields are invalid or ambiguous."""


def _merge(base, update):
    result = deepcopy(base)
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _load(path, stack):
    import yaml

    path = Path(path).resolve()
    if path in stack:
        raise ConfigurationError(f"Configuration inheritance cycle: {path}")
    with path.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if not isinstance(value, dict):
        raise ConfigurationError(f"Configuration must be an object: {path}")
    value = dict(value)
    parent = value.pop("extends", None)
    if parent is not None:
        if not isinstance(parent, str) or not parent.strip():
            raise ConfigurationError("extends must be a nonempty relative filename")
        value = _merge(_load(path.parent / parent, (*stack, path)), value)
    return value


def _positive_int(value, path):
    if type(value) is not int or value < 1:
        raise ConfigurationError(f"{path} must be a positive integer")


def _views(value, path):
    if (
        not isinstance(value, list)
        or not value
        or any(v not in VIEWS for v in value)
        or len(set(value)) != len(value)
    ):
        raise ConfigurationError(f"{path} must contain unique supported views: {VIEWS}")


def normalize_config(config):
    if not isinstance(config, dict):
        raise ConfigurationError("Configuration must be an object")
    config = deepcopy(config)
    try:
        llm = config["models"]["llm"]
        _positive_int(llm["max_tokens"], "models.llm.max_tokens")
        if (
            type(llm["temperature"]) not in (int, float)
            or not math.isfinite(llm["temperature"])
            or not 0 <= llm["temperature"] <= 2
        ):
            raise ConfigurationError("models.llm.temperature must be between 0 and 2")
        body = llm.get("extra_body") or {}
        if not isinstance(body, dict) or set(body) & {
            "temperature",
            "max_tokens",
            "max_output_tokens",
            "max_completion_tokens",
        }:
            raise ConfigurationError(
                "extra_body cannot override stage sampling parameters"
            )
        llm.setdefault("token_limit_parameter", "max_tokens")
        if llm["token_limit_parameter"] not in {"max_tokens", "max_completion_tokens"}:
            raise ConfigurationError(
                "token_limit_parameter must be max_tokens or max_completion_tokens"
            )
        llm.setdefault("temperature_policy", "send")
        if llm["temperature_policy"] not in {"send", "omit"}:
            raise ConfigurationError("temperature_policy must be send or omit")
        config.setdefault("experiment", {}).setdefault("variant", "full")
        if config["experiment"]["variant"] not in VARIANTS:
            raise ConfigurationError(f"experiment.variant must be one of {VARIANTS}")
        config["experiment"].setdefault("mode", "standard")
        if config["experiment"]["mode"] not in {"standard", "extended"}:
            raise ConfigurationError("experiment.mode must be standard or extended")
        config["experiment"].setdefault("schema_version", "1.0")
        if config["experiment"]["schema_version"] != "1.0":
            raise ConfigurationError("Unsupported experiment.schema_version")
        pricing = config["experiment"].setdefault("pricing_snapshot", None)
        if pricing is not None and (
            not isinstance(pricing, str) or not pricing.strip()
        ):
            raise ConfigurationError(
                "experiment.pricing_snapshot must be null or a nonempty path"
            )
        config.setdefault("sampling", {})
        if set(config["sampling"]) - set(SAMPLING_DEFAULTS):
            raise ConfigurationError("Unknown sampling stage")
        for stage, (temperature, max_tokens) in SAMPLING_DEFAULTS.items():
            options = config["sampling"].setdefault(stage, {})
            if set(options) - {"temperature", "max_tokens"}:
                raise ConfigurationError(f"Unknown sampling option for {stage}")
            options.setdefault(
                "temperature",
                llm["temperature"] if temperature is None else temperature,
            )
            options.setdefault(
                "max_tokens", llm["max_tokens"] if max_tokens is None else max_tokens
            )
            t = options["temperature"]
            if type(t) not in (int, float) or not math.isfinite(t) or not 0 <= t <= 2:
                raise ConfigurationError(
                    f"sampling.{stage}.temperature must be between 0 and 2"
                )
            _positive_int(options["max_tokens"], f"sampling.{stage}.max_tokens")
        _positive_int(
            config["models"]["embeddings"]["dimension"], "models.embeddings.dimension"
        )
        encoder = config["models"]["code_encoder"]
        if "graphcodebert" in config["models"]:
            raise ConfigurationError(
                "Configure models.code_encoder instead of the removed encoder"
            )
        if (
            not isinstance(encoder["model_name"], str)
            or not encoder["model_name"].strip()
            or not re.fullmatch(r"[0-9a-f]{40}", encoder["revision"])
        ):
            raise ConfigurationError(
                "Code encoder requires a model and immutable 40-character revision"
            )
        for key in ("max_length", "batch_size"):
            _positive_int(encoder[key], f"models.code_encoder.{key}")
        if (
            encoder["max_length"] < 2
            or encoder["pooling"] != "masked_mean"
            or encoder["truncation_side"] != "right"
            or encoder["dtype"] not in {"float32", "float16", "bfloat16"}
            or type(encoder["local_files_only"]) is not bool
        ):
            raise ConfigurationError("Invalid code encoding protocol")
        offline = config["offline"]["multiview"]
        _views(offline["views"], "offline.multiview.views")
        for name in ("prompts", "extraction_prompts"):
            paths = offline.get(name, {})
            if (
                not isinstance(paths, dict)
                or set(paths) - set(VIEWS)
                or any(
                    not isinstance(path, str) or not path.strip()
                    for path in paths.values()
                )
            ):
                raise ConfigurationError(
                    f"offline.multiview.{name} must map supported views to prompt paths"
                )
        dataset = config["offline"].setdefault("dataset", {})
        dataset.setdefault("max_code_length", None)
        if dataset["max_code_length"] is not None:
            _positive_int(dataset["max_code_length"], "offline.dataset.max_code_length")
        online = config["online"]
        context = online.setdefault("source_context", {"strategy": "full"})
        strategy = context.get("strategy")
        if strategy == "full":
            if set(context) != {"strategy"}:
                raise ConfigurationError(
                    "Full source context cannot carry unused range hints"
                )
        elif strategy == "line_range":
            if set(context) != {
                "strategy",
                "start_line",
                "end_line",
                "line_hint_source",
            }:
                raise ConfigurationError(
                    "line_range requires start_line, end_line and line_hint_source"
                )
            _positive_int(context["start_line"], "source_context.start_line")
            _positive_int(context["end_line"], "source_context.end_line")
            if (
                context["start_line"] > context["end_line"]
                or not isinstance(context["line_hint_source"], str)
                or not context["line_hint_source"].strip()
            ):
                raise ConfigurationError("Invalid source range or line_hint_source")
        else:
            raise ConfigurationError(
                "source_context.strategy must be full or line_range"
            )
        diagnosis = online["phase1_diagnosis"]
        diagnosis.setdefault(
            "tools", ["trace_data_flow", "is_path_reachable", "inspect_api_usage"]
        )
        diagnosis.setdefault("max_rounds", 15)
        diagnosis.setdefault("history_turns", 3)
        _positive_int(diagnosis["max_rounds"], "online.phase1_diagnosis.max_rounds")
        _positive_int(
            diagnosis["history_turns"], "online.phase1_diagnosis.history_turns"
        )
        tools = diagnosis["tools"]
        if (
            not isinstance(tools, list)
            or any(not isinstance(tool, str) or not tool for tool in tools)
            or len(set(tools)) != len(tools)
        ):
            raise ConfigurationError("Diagnostic tools must be a list of unique names")
        if set(tools) - {"trace_data_flow", "is_path_reachable", "inspect_api_usage"}:
            raise ConfigurationError(
                "Unsupported diagnostic tool; configure structured diagnosis tools"
            )
        retrieval = online["phase2_retrieval"]
        retrieval.setdefault("views", list(offline["views"]))
        _views(retrieval["views"], "online.phase2_retrieval.views")
        if config["experiment"]["mode"] == "standard":
            if config["models"]["embeddings"]["dimension"] != 384:
                raise ConfigurationError(
                    "standard mode requires 384-dimensional embeddings"
                )
        for section, key in (
            (online["phase1_diagnosis"], "max_tool_calls"),
            (retrieval, "top_k_per_view"),
            (retrieval, "final_top_k"),
            (online["phase3_repair"], "max_iterations"),
        ):
            _positive_int(section[key], key)
        weights = retrieval["reranking"]
        if set(weights) != {"code_weight", "behavior_weight", "bm25"}:
            raise ConfigurationError(
                "Reranking requires code_weight, behavior_weight and bm25"
            )
        values = [weights[k] for k in ("code_weight", "behavior_weight")]
        if any(
            type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1
            for v in values
        ) or not math.isclose(sum(values), 1):
            raise ConfigurationError(
                "code_weight and behavior_weight must be nonnegative and sum to 1"
            )
        bm25 = weights["bm25"]
        expected = {
            "statistics_scope": "candidate_pool",
            "normalization": "min_max",
            "equal_scores": "zero",
            "tokenizer": "identifier_words_v1",
        }
        if set(bm25) != {*expected, "k1", "b"} or any(
            bm25[key] != value for key, value in expected.items()
        ):
            raise ConfigurationError("Unsupported BM25 protocol")
        if (
            type(bm25["k1"]) not in (int, float)
            or not math.isfinite(bm25["k1"])
            or bm25["k1"] <= 0
            or type(bm25["b"]) not in (int, float)
            or not math.isfinite(bm25["b"])
            or not 0 <= bm25["b"] <= 1
        ):
            raise ConfigurationError("BM25 requires k1 > 0 and 0 <= b <= 1")
        repair = online["phase3_repair"]
        repair.setdefault("single_attempt", False)
        repair.setdefault("max_exemplars", retrieval["final_top_k"])
        _positive_int(repair["max_exemplars"], "online.phase3_repair.max_exemplars")
        for section, key in (
            (online["phase1_diagnosis"], "enabled"),
            (retrieval, "enabled"),
            (repair, "single_attempt"),
        ):
            if type(section[key]) is not bool:
                raise ConfigurationError(f"{key} must be a boolean")
    except (KeyError, TypeError, AttributeError) as exc:
        raise ConfigurationError(
            f"Missing or invalid configuration section: {exc}"
        ) from exc
    return config


def load_config(path):
    return normalize_config(_load(path, ()))


def resolve_offline_config(
    config, *, provider=None, model_name=None, base_url=None, views=None
):
    result = deepcopy(config)
    llm = result["models"]["llm"]
    for key, value in (
        ("provider", provider),
        ("model_name", model_name),
        ("base_url", base_url),
    ):
        if value is not None:
            llm[key] = value
    chosen = (
        list(views)
        if views is not None
        else (
            ["data_flow"]
            if result["experiment"]["variant"] == "df_only"
            else (
                ["control_flow"]
                if result["experiment"]["variant"] == "cf_only"
                else result["offline"]["multiview"]["views"]
            )
        )
    )
    result["offline"]["multiview"]["views"] = chosen
    if chosen == ["data_flow"] or chosen == ["control_flow"]:
        result["experiment"]["variant"] = (
            "df_only" if chosen == ["data_flow"] else "cf_only"
        )
    return normalize_config(result)


def resolve_online_config(
    config,
    *,
    provider=None,
    variant=None,
    no_diagnosis=False,
    no_retrieval=False,
    no_iteration=False,
    retrieval_view="all",
):
    result = normalize_config(config)
    if provider is not None:
        result["models"]["llm"]["provider"] = provider
    online = result["online"]
    selected = set()
    requested = variant or result["experiment"]["variant"]
    if requested not in VARIANTS:
        raise ConfigurationError(f"Unknown variant: {requested}")
    if requested != "full":
        selected.add(requested)
    for name, enabled in (
        ("no_diagnosis", no_diagnosis or not online["phase1_diagnosis"]["enabled"]),
        ("no_retrieval", no_retrieval or not online["phase2_retrieval"]["enabled"]),
        ("no_iteration", no_iteration or online["phase3_repair"]["single_attempt"]),
    ):
        if enabled:
            selected.add(name)
    view_modes = {"data_flow": "df_only", "control_flow": "cf_only"}
    if retrieval_view not in {"all", *VIEWS}:
        raise ConfigurationError(
            "retrieval_view must be all, data_flow or control_flow"
        )
    if retrieval_view != "all":
        selected.add(view_modes[retrieval_view])
    views = online["phase2_retrieval"]["views"]
    if len(views) == 1:
        selected.add(view_modes[views[0]])
    if len(selected) > 1:
        raise ConfigurationError(
            f"Choose one ablation variant, not a combination: {sorted(selected)}"
        )
    effective = next(iter(selected), "full")
    if variant == "full" and effective != "full":
        raise ConfigurationError(
            "Explicit full variant conflicts with disabled components or restricted views"
        )
    result["experiment"]["variant"] = effective
    active_views = (
        ["data_flow"]
        if effective == "df_only"
        else ["control_flow"] if effective == "cf_only" else list(VIEWS)
    )
    online["phase2_retrieval"]["views"] = active_views
    online["phase2_retrieval"]["enabled"] = effective != "no_retrieval"
    online["phase1_diagnosis"]["enabled"] = effective != "no_diagnosis"
    online["phase3_repair"]["single_attempt"] = effective == "no_iteration"
    return normalize_config(result)
