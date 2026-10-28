"""Versioned, dependency-free contracts for pipeline boundaries.

These contracts describe validated data. Legacy analysis text must not be cast to
verified facts, and absent validation stages must remain ``not_run``.
"""

from dataclasses import asdict, dataclass, field, fields
from enum import Enum
import types
from typing import (
    Any,
    Dict,
    List,
    Literal,
    Optional,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)


SCHEMA_VERSION = "1.0"
ViewType = Literal["data_flow", "control_flow"]


class ContractError(ValueError):
    """A record violates a boundary contract."""


class StageStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"
    ERROR = "error"


def _decode(value, annotation, path):
    origin = get_origin(annotation)
    args = get_args(annotation)
    if annotation is Any:
        return value
    if origin in (Union, types.UnionType):
        for item in args:
            try:
                return _decode(value, item, path)
            except ContractError:
                pass
        raise ContractError(f"{path}: incompatible value {value!r}")
    if origin is Literal:
        if value not in args or not any(type(value) is type(item) for item in args):
            raise ContractError(f"{path}: expected one of {args}")
        return value
    if origin is list:
        if not isinstance(value, list):
            raise ContractError(f"{path}: expected a list")
        return [_decode(item, args[0], f"{path}[{i}]") for i, item in enumerate(value)]
    if origin is dict:
        if not isinstance(value, dict):
            raise ContractError(f"{path}: expected an object")
        return {
            _decode(k, args[0], path): _decode(v, args[1], f"{path}.{k}")
            for k, v in value.items()
        }
    if isinstance(annotation, type) and issubclass(annotation, Contract):
        if isinstance(value, annotation):
            value.__post_init__()
            return value
        return annotation.from_dict(value)
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        try:
            return annotation(value)
        except (ValueError, TypeError) as exc:
            raise ContractError(f"{path}: invalid status {value!r}") from exc
    if annotation is type(None):
        if value is not None:
            raise ContractError(f"{path}: expected null")
    elif annotation is float:
        if type(value) not in (int, float):
            raise ContractError(f"{path}: expected a number")
    elif type(value) is not annotation:
        raise ContractError(f"{path}: expected {annotation.__name__}")
    return value


class Contract:
    def __post_init__(self):
        for name, annotation in get_type_hints(type(self)).items():
            setattr(
                self,
                name,
                _decode(
                    getattr(self, name), annotation, f"{type(self).__name__}.{name}"
                ),
            )
        if self.schema_version != SCHEMA_VERSION:
            raise ContractError(f"Unsupported schema version: {self.schema_version}")

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ContractError(f"{cls.__name__}: expected an object")
        unknown = set(value) - {item.name for item in fields(cls)}
        if unknown:
            raise ContractError(f"{cls.__name__}: unknown fields {sorted(unknown)}")
        try:
            return cls(**value)
        except TypeError as exc:
            raise ContractError(f"{cls.__name__}: {exc}") from exc

    def to_dict(self):
        # Revalidate mutable collections before crossing a serialization boundary.
        self.__post_init__()
        return asdict(self)


def _nonempty(value, name):
    if not value.strip():
        raise ContractError(f"{name} must not be empty")


@dataclass
class KnowledgeItems(Contract):
    root_cause: str
    risky_calls: List[str]
    fixing_strategy: str
    taint_flow: Optional[str] = None
    control_branch: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        super().__post_init__()
        _nonempty(self.root_cause, "root_cause")
        _nonempty(self.fixing_strategy, "fixing_strategy")
        for call in self.risky_calls:
            _nonempty(call, "risky_calls item")


@dataclass
class KnowledgeRecord(Contract):
    sample_id: str
    cve_id: str
    project: str
    language: str
    source_provenance: Dict[str, Any]
    cve_description: str
    buggy_code: str
    fixed_code: str
    patch: str
    view_type: ViewType
    extracted_knowledge: KnowledgeItems
    abstracted_knowledge: KnowledgeItems
    extraction_model: str
    prompt_hash: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        super().__post_init__()
        for name in (
            "sample_id",
            "cve_description",
            "buggy_code",
            "extraction_model",
            "prompt_hash",
        ):
            _nonempty(getattr(self, name), name)
        if not (self.fixed_code.strip() or self.patch.strip()):
            raise ContractError("KnowledgeRecord requires fixed_code or patch")
        required = {"data_flow": "taint_flow", "control_flow": "control_branch"}.get(
            self.view_type
        )
        if required:
            for name in ("extracted_knowledge", "abstracted_knowledge"):
                if not (getattr(getattr(self, name), required) or "").strip():
                    raise ContractError(
                        f"{name}.{required} is required for {self.view_type}"
                    )


@dataclass
class SourceLocation(Contract):
    file_path: str
    start_line: int
    end_line: int
    schema_version: str = SCHEMA_VERSION
    start_column: Optional[int] = None
    end_column: Optional[int] = None

    def __post_init__(self):
        super().__post_init__()
        _nonempty(self.file_path, "file_path")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ContractError(
                "Source locations require a positive, ordered line range"
            )
        for value in (self.start_column, self.end_column):
            if value is not None and value < 1:
                raise ContractError("Source columns must be positive")
        if (
            self.start_line == self.end_line
            and self.start_column is not None
            and self.end_column is not None
            and self.end_column < self.start_column
        ):
            raise ContractError("Source columns must form an ordered range")


@dataclass
class ProgramFact(Contract):
    statement: str
    location: SourceLocation
    tool: str
    evidence_id: str
    schema_version: str = SCHEMA_VERSION
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        super().__post_init__()
        for name in ("statement", "tool", "evidence_id"):
            _nonempty(getattr(self, name), name)


@dataclass
class DiagnosticReport(Contract):
    mode: Literal["tool_grounded", "llm_only"]
    facts: List[ProgramFact]
    hypotheses: List[str]
    tool_calls: List[Dict[str, Any]]
    termination_reason: str
    schema_version: str = SCHEMA_VERSION
    root_causes_by_view: Dict[str, str] = field(default_factory=dict)
    summary: str = ""
    keywords: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    reasoning_call_count: int = 0
    report_call_count: int = 0
    tool_call_count: int = 0
    usage: Dict[str, Any] = field(default_factory=dict)
    summary_evidence_ids: List[str] = field(default_factory=list)

    def __post_init__(self):
        super().__post_init__()
        if self.mode == "llm_only" and (self.facts or self.tool_calls):
            raise ContractError(
                "llm_only reports cannot claim tool-verified facts or tool calls"
            )
        if set(self.root_causes_by_view) - {"data_flow", "control_flow"}:
            raise ContractError("Unknown root-cause view")
        _nonempty(self.termination_reason, "termination_reason")
        if (
            min(self.reasoning_call_count, self.report_call_count, self.tool_call_count)
            < 0
        ):
            raise ContractError("Diagnostic counters must not be negative")
        identifiers = [fact.evidence_id for fact in self.facts]
        if len(set(identifiers)) != len(identifiers):
            raise ContractError("Diagnostic evidence IDs must be unique")
        if set(self.summary_evidence_ids) - set(identifiers):
            raise ContractError("Summary references nonexistent evidence IDs")
        observed = {}
        for call in self.tool_calls:
            if call.get("status") == "completed" and isinstance(
                call.get("observation"), dict
            ):
                for fact in call["observation"].get("facts", []):
                    validated = ProgramFact.from_dict(fact)
                    if validated.tool != call.get("tool"):
                        raise ContractError(
                            "Evidence tool does not match its tool-call record"
                        )
                    observed[validated.evidence_id] = validated
        if any(observed.get(fact.evidence_id) != fact for fact in self.facts):
            raise ContractError(
                "Each diagnostic fact must match a completed tool observation"
            )


@dataclass
class ValidationResult(Contract):
    candidate_id: str
    raw_patch_hash: str
    effective_patch_hash: Optional[str] = None
    generated_patch_hash: Optional[str] = None
    corrected_patch_hash: Optional[str] = None
    patch_correction: Dict[str, Any] = field(default_factory=dict)
    patch_apply_status: StageStatus = StageStatus.NOT_RUN
    compile_status: StageStatus = StageStatus.NOT_RUN
    poc_status: StageStatus = StageStatus.NOT_RUN
    unit_status: StageStatus = StageStatus.NOT_RUN
    failed_stage: Optional[Literal["patch_apply", "compile", "poc", "unit"]] = None
    error_log: str = ""
    artifacts: Dict[str, str] = field(default_factory=dict)
    original_source_hash: Optional[str] = None
    validated_source_hash: Optional[str] = None
    stage_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    docker_image: Optional[str] = None
    docker_digest: Optional[str] = None
    stage: Optional[str] = None
    docker_step: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        super().__post_init__()
        _nonempty(self.candidate_id, "candidate_id")
        _nonempty(self.raw_patch_hash, "raw_patch_hash")
        stages = self.stage_status
        if self.failed_stage and stages[self.failed_stage] not in (
            StageStatus.FAILED,
            StageStatus.ERROR,
        ):
            raise ContractError("failed_stage must identify a failed or errored stage")
        if self.success and not self.effective_patch_hash:
            raise ContractError(
                "Successful validation requires the effective patch hash"
            )

    @property
    def stage_status(self):
        return {
            name: getattr(self, f"{name}_status")
            for name in ("patch_apply", "compile", "poc", "unit")
        }

    @property
    def success(self):
        return all(
            status == StageStatus.PASSED for status in self.stage_status.values()
        )

    @property
    def patch_apply_pass(self):
        return self.patch_apply_status == StageStatus.PASSED

    @property
    def compile_pass(self):
        return self.compile_status == StageStatus.PASSED

    @property
    def poc_pass(self):
        return self.poc_status == StageStatus.PASSED

    @property
    def unit_pass(self):
        return self.unit_status == StageStatus.PASSED

    def to_dict(self):
        result = super().to_dict()
        result["success"] = self.success
        result["stage_status"] = self.stage_status
        for name in self.stage_status:
            result[f"{name}_pass"] = getattr(self, f"{name}_pass")
        return result

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ContractError("ValidationResult: expected an object")
        data = dict(value)
        has_success = "success" in data
        has_stages = "stage_status" in data
        declared_success = data.pop("success", None)
        declared_stages = data.pop("stage_status", None)
        declared_flags = {
            key: data.pop(key)
            for key in tuple(data)
            if key in {"patch_apply_pass", "compile_pass", "poc_pass", "unit_pass"}
        }
        result = super().from_dict(data)
        if has_success and (
            type(declared_success) is not bool or declared_success != result.success
        ):
            raise ContractError("success disagrees with validation stages")
        if has_stages and declared_stages != result.stage_status:
            raise ContractError("stage_status disagrees with validation stages")
        for name, value in declared_flags.items():
            if type(value) is not bool or value != getattr(result, name):
                raise ContractError(f"{name} disagrees with validation stages")
        return result


@dataclass
class RepairResult(Contract):
    success: bool
    final_patch: Optional[str]
    iterations: int
    history: List[Dict[str, Any]]
    generation_count: int
    validation_count: int
    llm_call_count: int
    termination_reason: str
    experiment_id: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        super().__post_init__()
        for name in (
            "iterations",
            "generation_count",
            "validation_count",
            "llm_call_count",
        ):
            if getattr(self, name) < 0:
                raise ContractError(f"{name} must not be negative")
        if self.success and (not self.final_patch or not self.final_patch.strip()):
            raise ContractError("Successful repairs require a final patch")
        for name in ("termination_reason", "experiment_id"):
            _nonempty(getattr(self, name), name)
