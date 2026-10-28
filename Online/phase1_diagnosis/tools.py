"""LangChain structured tools bound to one immutable source snapshot."""

import json
from typing import Annotated

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr
from static_analysis.memory import ACCESS_PATTERN


class SourcePosition(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    line: Annotated[StrictInt, Field(ge=1)]
    column: Annotated[StrictInt, Field(ge=1)] | None = None


Variable = Annotated[StrictStr, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]
TraceVariable = Annotated[StrictStr, Field(pattern=ACCESS_PATTERN, max_length=256)]


class TraceArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    variable: TraceVariable
    statement: SourcePosition


class PathArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source: SourcePosition
    target: SourcePosition
    variable: Variable | None = None
    max_paths: Annotated[StrictInt, Field(ge=1, le=32)] = 8


class CallArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    call: SourcePosition


TOOL_NAMES = ("trace_data_flow", "is_path_reachable", "inspect_api_usage")


def create_diagnostic_tools(session, enabled_tools=None):
    """ToolNode executes these tools and preserves their complete result artifacts."""

    def as_tool(name, arguments, description, query):
        def execute(**values):
            result = query(**values)
            return json.dumps(result, ensure_ascii=False), result

        return StructuredTool.from_function(
            execute,
            name=name,
            description=description,
            args_schema=arguments,
            response_format="content_and_artifact",
        )

    tools = {
        "trace_data_flow": as_tool(
            "trace_data_flow",
            TraceArguments,
            "Trace intraprocedural may-data-flow for a variable/access path (x, obj.field, p->field, arr[0], arr[i], *p) at a 1-based source position. Tracks local pointer aliases, fields, array writes and conservative API/output-argument effects. Unknown aliases, external inputs and call effects stay explicit. Does not prove taint or runtime feasibility.",
            session.trace_data_flow,
        ),
        "is_path_reachable": as_tool(
            "is_path_reachable",
            PathArguments,
            "Enumerate bounded simple CFG paths in one function, with branch outcomes, variable-related checks, required dominating conditions (including before the source), and control dependencies. max_paths defaults to 8, at most 32. Search budgets and omitted loop iterations are explicit; runtime feasibility remains unknown.",
            session.is_path_reachable,
        ),
        "inspect_api_usage": as_tool(
            "inspect_api_usage",
            CallArguments,
            "Inspect a call at a source position: callee, receiver, arguments, return-value context, enclosing function, surrounding source, and same-file implementation candidates. Supply a column if several calls share a line.",
            session.inspect_api_usage,
        ),
    }
    selected = list(TOOL_NAMES) if enabled_tools is None else list(enabled_tools)
    if len(set(selected)) != len(selected) or set(selected) - set(TOOL_NAMES):
        raise ValueError(
            "Diagnostic tools must be unique supported structured tool names"
        )
    return [tools[name] for name in selected]
