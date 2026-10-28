"""LangGraph ReAct diagnosis with native LangChain tool messages and evidence state."""

import json
from importlib.metadata import version
from pathlib import Path
from utils.chat_calls import chat_call
import time
from uuid import uuid4
from typing import Annotated, TypedDict

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, ConfigDict, Field

from static_analysis.session import AnalysisSession
from static_analysis.treesitter_wrapper import infer_language
from utils.diagnostics import enhanced_context
from utils.experiment_manifest import hash_file, hash_object, sanitize_config
from utils.schemas import DiagnosticReport, ProgramFact
from utils.runtime_progress import progress_event

from .tools import TOOL_NAMES, create_diagnostic_tools


class RootCauseHypotheses(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data_flow: str | None = None
    control_flow: str | None = None


class DiagnosisSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(default="", description="One integrated diagnosis of the suspected vulnerability mechanism and its uncertainty")
    hypotheses: list[str] = Field(
        description="Unverified interpretations, never tool facts"
    )
    root_causes_by_view: RootCauseHypotheses = Field(
        default_factory=RootCauseHypotheses,
        description="Optional legacy field; leave empty. Retrieval generates its own view-specific queries.",
    )
    keywords: list[str]
    evidence_ids: list[str] = Field(
        description="Only IDs supplied in the evidence state"
    )


class DiagnosisState(TypedDict):
    source_id: str
    messages: Annotated[list[BaseMessage], add_messages]
    facts: dict
    tool_calls: list
    limitations: list
    reasoning_call_count: int
    report_call_count: int
    tool_call_count: int
    pending_calls: list
    termination_reason: str
    usage: list
    report: dict


class DiagnosticAgent:
    def __init__(
        self,
        model,
        report_model=None,
        *,
        max_rounds=15,
        max_tool_calls=15,
        history_turns=3,
        enabled_tools=None,
        checkpointer=None,
    ):
        if (
            not isinstance(model, BaseChatModel)
            or report_model is not None
            and not isinstance(report_model, BaseChatModel)
        ):
            raise TypeError(
                "DiagnosticAgent requires LangChain BaseChatModel instances with native tool calling"
            )
        for value in (max_rounds, max_tool_calls, history_turns):
            if type(value) is not int or value < 1:
                raise ValueError(
                    "Diagnostic budgets and history_turns must be positive integers"
                )
        self.model, self.report_model = model, report_model or model
        self.max_rounds, self.max_tool_calls, self.history_turns = (
            max_rounds,
            max_tool_calls,
            history_turns,
        )
        self.enabled_tools = (
            list(TOOL_NAMES) if enabled_tools is None else list(enabled_tools)
        )
        if len(set(self.enabled_tools)) != len(self.enabled_tools) or set(
            self.enabled_tools
        ) - set(TOOL_NAMES):
            raise ValueError("Unknown or duplicate diagnostic tools")
        self.checkpointer = checkpointer
        path = (
            Path(__file__).resolve().parents[2]
            / "prompts/online/diagnosis/initial_analysis.txt"
        )
        self.prompt = path.read_text(encoding="utf-8")
        self.graph = None
        root = Path(__file__).resolve().parents[2]
        sources = [
            *Path(__file__).parent.glob("*.py"),
            *(root / "static_analysis").glob("*.py"),
            root / "models/chat.py",
            root / "utils/schemas.py",
            root / "utils/diagnostics.py",
        ]
        self.runtime_identity = {
            "implementation": {
                str(source.relative_to(root)): hash_file(source)
                for source in sorted(sources)
            },
            "packages": {
                name: version(name)
                for name in (
                    "langchain-core",
                    "langgraph",
                    "langgraph-prebuilt",
                    "tree-sitter",
                    "networkx",
                    "pydantic",
                )
            },
        }

    @staticmethod
    def _model_identity(model):
        fields = (
            "model",
            "model_name",
            "temperature",
            "max_tokens",
            "max_output_tokens",
            "openai_api_base",
            "anthropic_api_url",
            "base_url",
            "max_retries",
            "model_kwargs",
            "extra_body",
        )
        values = {
            name: value
            for name in fields
            if isinstance(
                value := getattr(model, name, None),
                (str, int, float, bool, dict, list, type(None)),
            )
        }
        return {
            "class": f"{type(model).__module__}.{type(model).__qualname__}",
            "parameters": sanitize_config(values),
        }

    def _usage(self, message, stage, elapsed, error=None):
        usage = getattr(message, "usage_metadata", None)
        model = self.report_model if stage == "report" else self.model
        simulation = getattr(model, "_llm_type", None) == "diagnostic-mock"
        if simulation:
            usage = None
        return {
            "stage": stage,
            "simulation": simulation,
            "input_tokens": usage.get("input_tokens") if usage else None,
            "output_tokens": usage.get("output_tokens") if usage else None,
            "total_tokens": usage.get("total_tokens") if usage else None,
            "elapsed_seconds": elapsed,
            "error": error,
        }

    def _recent_messages(self, messages):
        # Keep complete model/tool groups, so a ToolMessage never loses its caller.
        groups, current = [], []
        for message in messages[1:]:
            if isinstance(message, AIMessage) and current:
                groups.append(current)
                current = []
            current.append(message)
        if current:
            groups.append(current)
        recent = messages[:1] + [
            message for group in groups[-self.history_turns :] for message in group
        ]
        return [
            (
                message.model_copy(
                    update={
                        "content": str(message.content)[:8000]
                        + "\n[Observation excerpt; complete evidence remains in state.]"
                    }
                )
                if isinstance(message, ToolMessage) and len(str(message.content)) > 8000
                else message
            )
            for message in recent
        ]

    def _compile(self, session):
        tools = create_diagnostic_tools(session, self.enabled_tools)
        reasoning = self.model.bind_tools(tools) if tools else self.model
        reporter = self.report_model.bind_tools([DiagnosisSummary], tool_choice="auto")

        def reason(state):
            started = time.monotonic()
            count = state["reasoning_call_count"] + 1
            memory = json.dumps(
                {
                    "facts": list(state["facts"].values()),
                    "limitations": state["limitations"],
                    "remaining_rounds": self.max_rounds - count,
                    "remaining_tool_calls": self.max_tool_calls
                    - state["tool_call_count"],
                },
                ensure_ascii=False,
            )
            try:
                response = chat_call(
                    reasoning,
                    [
                        SystemMessage(
                            content=self.prompt
                            + "\n\nAccumulated evidence and budgets:\n"
                            + memory
                        ),
                        *self._recent_messages(state["messages"]),
                    ],
                    "diagnosis",
                    model=self.model,
                )
                if not isinstance(response, AIMessage):
                    raise TypeError("Chat model must return an AIMessage")
                calls = response.tool_calls
                reason = "model_finished" if not calls else ""
                if response.invalid_tool_calls:
                    reason = "invalid_tool_call"
                identifiers = [call["id"] for call in calls]
                if len(set(identifiers)) != len(identifiers) or any(
                    not identifier for identifier in identifiers
                ):
                    reason = "invalid_tool_call"
                return {
                    "messages": [response],
                    "reasoning_call_count": count,
                    "pending_calls": calls,
                    "termination_reason": reason,
                    "usage": state["usage"]
                    + [self._usage(response, "reasoning", time.monotonic() - started)],
                }
            except Exception as exc:
                return {
                    "reasoning_call_count": count,
                    "pending_calls": [],
                    "termination_reason": "model_error",
                    "limitations": state["limitations"]
                    + [f"Reasoning request failed: {type(exc).__name__}: {exc}"],
                    "usage": state["usage"]
                    + [
                        self._usage(
                            None, "reasoning", time.monotonic() - started, str(exc)
                        )
                    ],
                }

        def route(state):
            if state["termination_reason"]:
                return "report"
            if (
                len(state["pending_calls"])
                > self.max_tool_calls - state["tool_call_count"]
            ):
                return "budget"
            progress_event("Running diagnostic tools: " + ", ".join(call["name"] for call in state["pending_calls"]), "running", kind="tool")
            return "tools"

        def budget(state):
            rejected = [
                {
                    "call_id": call["id"],
                    "tool": call["name"],
                    "arguments": call["args"],
                    "status": "budget_rejected",
                    "observation": "Not executed: the batch exceeds the remaining tool-call budget.",
                }
                for call in state["pending_calls"]
            ]
            return {
                "tool_calls": state["tool_calls"] + rejected,
                "termination_reason": "tool_budget_exhausted",
                "limitations": state["limitations"]
                + [
                    "The requested tool batch exceeds the remaining tool-call budget; no calls in that batch were executed."
                ],
            }

        def observe(state):
            count = len(state["pending_calls"])
            observations = state["messages"][-count:] if count else []
            facts, calls, limitations = (
                dict(state["facts"]),
                list(state["tool_calls"]),
                list(state["limitations"]),
            )
            for requested, message in zip(state["pending_calls"], observations):
                if (
                    not isinstance(message, ToolMessage)
                    or message.tool_call_id != requested["id"]
                ):
                    raise RuntimeError(
                        "ToolNode result does not match the requested tool call"
                    )
                artifact = (
                    message.artifact if isinstance(message.artifact, dict) else None
                )
                succeeded = message.status != "error" and artifact is not None
                progress_event("Tool result: " + requested["name"], "completed" if succeeded else "failed",
                               kind="tool", tool=requested["name"], fact_count=len(artifact.get("facts", [])) if succeeded else 0)
                calls.append(
                    {
                        "call_id": requested["id"],
                        "tool": requested["name"],
                        "arguments": requested["args"],
                        "status": "completed" if succeeded else "error",
                        "observation": artifact if succeeded else str(message.content),
                    }
                )
                if succeeded:
                    for fact in artifact["facts"]:
                        validated = ProgramFact.from_dict(fact).to_dict()
                        facts[validated["evidence_id"]] = validated
                    limitations.extend(artifact["limitations"])
                else:
                    limitations.append(
                        f"Tool {requested['name']} failed; its output contributes no verified facts."
                    )
            total = state["tool_call_count"] + count
            termination = (
                "tool_budget_exhausted"
                if total >= self.max_tool_calls
                else (
                    "round_budget_exhausted"
                    if state["reasoning_call_count"] >= self.max_rounds
                    else ""
                )
            )
            return {
                "facts": facts,
                "tool_calls": calls,
                "tool_call_count": total,
                "limitations": sorted(set(limitations)),
                "termination_reason": termination,
            }

        def report(state):
            summary = DiagnosisSummary(
                hypotheses=[], root_causes_by_view={}, keywords=[], evidence_ids=[]
            )
            limitations = list(state["limitations"])
            # Keep one copy of each observation payload; fact records otherwise repeat
            # the same large result for every evidence ID.
            facts, payloads = [], {}
            for fact in state["facts"].values():
                key = hash_object(fact.get("details", {}))
                first_id = payloads.setdefault(key, fact["evidence_id"])
                facts.append({**fact, "details": fact.get("details", {}) if first_id == fact["evidence_id"] else {},
                              "details_evidence_id": first_id})
            messages = [
                SystemMessage(content=(
                    "Generate a structured diagnostic summary from source-bound evidence. "
                    "Call DiagnosisSummary, or return ONLY a JSON object matching its schema. "
                    "No Markdown or prose outside JSON. Write one integrated vulnerability "
                    "diagnosis in summary, expressing uncertainty when evidence is limited. "
                    "Do not split the diagnosis into retrieval perspectives; leave the optional "
                    "legacy root_causes_by_view field empty. The retrieval stage generates "
                    "data-flow and control-flow queries from this report separately. "
                    "Tool facts are structural observations, not runtime proof. Interpretations "
                    "belong in hypotheses, never in facts. Cite only supplied evidence IDs. "
                    "If no evidence exists, state that limitation. Schema: "
                    + json.dumps(DiagnosisSummary.model_json_schema())
                )),
                HumanMessage(content=json.dumps({
                    "facts": facts,
                    "source": state["messages"][0].content,
                    "analysis_notes": [m.content for m in state["messages"]
                                       if isinstance(m, AIMessage) and m.content],
                    "limitations": limitations,
                    "termination_reason": state["termination_reason"],
                }, ensure_ascii=False)),
            ]
            usage = list(state["usage"])
            error, attempts = None, 0
            for attempt in range(3):
                raw, error = None, None
                started = time.monotonic()
                attempts += 1
                try:
                    raw = chat_call(reporter, messages, "diagnosis_report", model=self.report_model)
                    calls = [c for c in raw.tool_calls if c.get("name") == "DiagnosisSummary"]
                    if calls:
                        if len(calls) != 1:
                            raise ValueError("Expected exactly one DiagnosisSummary")
                        summary = DiagnosisSummary.model_validate(calls[0]["args"])
                    else:
                        content = raw.content
                        if isinstance(content, list):
                            content = "".join(x.get("text", "") for x in content if isinstance(x, dict))
                        content = content.strip()
                        if content.startswith("```") and content.endswith("```"):
                            content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()
                        summary = DiagnosisSummary.model_validate_json(content)
                    if set(summary.evidence_ids) - set(state["facts"]):
                        raise ValueError("The report referenced nonexistent evidence IDs")
                    break
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                    summary = DiagnosisSummary(hypotheses=[], root_causes_by_view={}, keywords=[], evidence_ids=[])
                    # Retry format/field failures, without treating narrative as a report.
                    if not isinstance(exc, ValueError) or attempt == 2:
                        break
                    messages.append(HumanMessage(content=(
                        "The last summary failed schema validation: " + error[:1200]
                        + ". Return a valid DiagnosisSummary using the original evidence."
                    )))
                finally:
                    usage.append(self._usage(raw, "report", time.monotonic() - started, error))
            if error is not None:
                limitations.append("Final model summary unavailable or invalid: " + error)
            termination = state["termination_reason"] or "model_finished"
            if error is not None:
                termination += ":report_error"
            record = DiagnosticReport(
                mode="tool_grounded" if state["tool_calls"] else "llm_only",
                facts=list(state["facts"].values()),
                hypotheses=summary.hypotheses,
                summary=summary.summary,
                root_causes_by_view=summary.root_causes_by_view.model_dump(
                    exclude_none=True
                ),
                tool_calls=state["tool_calls"],
                termination_reason=termination,
                keywords=summary.keywords,
                limitations=sorted(set(limitations)),
                reasoning_call_count=state["reasoning_call_count"],
                report_call_count=attempts,
                summary_evidence_ids=summary.evidence_ids,
                tool_call_count=state["tool_call_count"],
                usage={
                    "model_calls": usage,
                    "tokens_complete": all(
                        item["total_tokens"] is not None for item in usage
                    ),
                    "reported_total_tokens": (
                        sum(item["total_tokens"] for item in usage)
                        if all(item["total_tokens"] is not None for item in usage)
                        else None
                    ),
                    "known_total_tokens": sum(
                        item["total_tokens"]
                        for item in usage
                        if item["total_tokens"] is not None
                    ),
                },
            ).to_dict()
            return {"report": record, "report_call_count": attempts, "usage": usage}

        builder = StateGraph(DiagnosisState)
        builder.add_node("reason", reason)
        builder.add_node("tools", ToolNode(tools, handle_tool_errors=True))
        builder.add_node("observe", observe)
        builder.add_node("budget", budget)
        builder.add_node("report", report)
        builder.add_edge(START, "reason")
        builder.add_conditional_edges(
            "reason", route, {"tools": "tools", "budget": "budget", "report": "report"}
        )
        builder.add_edge("tools", "observe")
        builder.add_conditional_edges(
            "observe",
            lambda state: "report" if state["termination_reason"] else "reason",
            {"report": "report", "reason": "reason"},
        )
        builder.add_edge("budget", "report")
        builder.add_edge("report", END)
        return builder.compile(checkpointer=self.checkpointer)

    def diagnose(
        self,
        buggy_code,
        *,
        file_path,
        language=None,
        line_offset=0,
        focus_window=None,
        run_id=None,
    ):
        try:
            selected_language = infer_language(file_path, language)
            session = AnalysisSession(
                buggy_code,
                language=selected_language,
                file_path=file_path,
                line_offset=line_offset,
            )
        except (ValueError, ImportError) as exc:
            record = DiagnosticReport(
                mode="llm_only",
                facts=[],
                hypotheses=[],
                root_causes_by_view={},
                tool_calls=[],
                termination_reason="analysis_unavailable",
                limitations=[str(exc)],
            ).to_dict()
            return {
                "diagnostic_report": record,
                "enhanced_context": enhanced_context(buggy_code, record),
            }
        lines = buggy_code.splitlines()
        start = int(focus_window["window_offset"]) if focus_window else 0
        stop = (
            start + int(focus_window["window_line_count"])
            if focus_window
            else len(lines)
        )
        numbered = "\n".join(
            f"{index + 1 + line_offset}: {lines[index]}"
            for index in range(start, min(stop, len(lines)))
        )
        identity = hash_object(
            {
                "code": buggy_code,
                "path": str(file_path),
                "language": selected_language,
                "offset": line_offset,
                "max_rounds": self.max_rounds,
                "max_tool_calls": self.max_tool_calls,
                "tools": self.enabled_tools,
                "history_turns": self.history_turns,
                "focus_window": {"start": start, "stop": stop},
                "prompt": self.prompt,
                "model": self._model_identity(self.model),
                "report_model": self._model_identity(self.report_model),
                "runtime": self.runtime_identity,
            }
        )
        initial = DiagnosisState(
            source_id=identity,
            messages=[
                HumanMessage(
                    content=f"Source: {file_path}\nLanguage: {selected_language}\nLine-numbered focus window; tools analyze the complete supplied source (columns refer to the original code):\n{numbered}"
                )
            ],
            facts={},
            tool_calls=[],
            limitations=session.source.limitations,
            reasoning_call_count=0,
            report_call_count=0,
            tool_call_count=0,
            pending_calls=[],
            termination_reason="",
            usage=[],
            report={},
        )
        graph = self._compile(session)
        self.graph = graph
        config = {
            "recursion_limit": 3 * self.max_rounds + 5,
            "configurable": {"thread_id": run_id or str(uuid4())},
        }
        snapshot = graph.get_state(config) if self.checkpointer else None
        if snapshot and snapshot.values:
            if snapshot.values.get("source_id") != identity:
                raise ValueError(
                    "Diagnostic checkpoint source, model, prompts, runtime or budgets do not match this run"
                )
            result = (
                graph.invoke(None, config=config) if snapshot.next else snapshot.values
            )
        else:
            result = graph.invoke(initial, config=config)
        return {
            "diagnostic_report": result["report"],
            "enhanced_context": enhanced_context(buggy_code, result["report"]),
        }
