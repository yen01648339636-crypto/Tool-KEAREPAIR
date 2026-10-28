"""Native LangChain model fixtures; no text-protocol agent simulations."""

from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

from models.chat import DiagnosticMockModel
from utils.schemas import DiagnosticReport, ProgramFact, SourceLocation


def diagnostic_report(statement="A structural observation"):
    fact = ProgramFact(
        statement=statement,
        location=SourceLocation("example.c", 1, 1),
        tool="inspect_api_usage",
        evidence_id="fixture-evidence",
    )
    return DiagnosticReport(
        mode="tool_grounded",
        facts=[fact],
        hypotheses=[],
        root_causes_by_view={},
        tool_calls=[
            {
                "tool": "inspect_api_usage",
                "status": "completed",
                "observation": {"facts": [fact.to_dict()]},
            }
        ],
        termination_reason="model_finished",
    ).to_dict()


class ScriptedChatModel(DiagnosticMockModel):
    responses: list = Field(default_factory=list)
    requests: list = Field(default_factory=list)
    report_payload: dict | None = None
    report_error: bool = False

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.requests.append(messages)
        tools = kwargs.get("tools", [])
        report = any(tool["function"]["name"] == "DiagnosisSummary" for tool in tools)
        if report:
            if self.report_error:
                raise RuntimeError("local report failure")
            if self.report_payload is not None:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "name": "DiagnosisSummary",
                                        "args": self.report_payload,
                                        "id": "report",
                                    }
                                ],
                                usage_metadata={
                                    "input_tokens": 7,
                                    "output_tokens": 3,
                                    "total_tokens": 10,
                                },
                            )
                        )
                    ]
                )
            return super()._generate(messages, stop, run_manager, **kwargs)
        response = (
            self.responses.pop(0) if self.responses else AIMessage(content="Done")
        )
        if isinstance(response, Exception):
            raise response
        return ChatResult(generations=[ChatGeneration(message=response)])


def call(name, arguments, identifier="tool-1"):
    return AIMessage(
        content="",
        tool_calls=[{"name": name, "args": arguments, "id": identifier}],
        usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
    )
