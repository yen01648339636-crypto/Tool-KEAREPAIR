"""LangChain chat models for native tool calling and diagnostic reports."""

import os

from langchain.chat_models import init_chat_model
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool


class DiagnosticMockModel(BaseChatModel):
    """Explicit local simulation using the same LangChain message/tool protocol."""

    @property
    def _llm_type(self):
        return "diagnostic-mock"

    def bind_tools(self, tools, **kwargs):
        return self.bind(
            tools=[convert_to_openai_tool(tool) for tool in tools], **kwargs
        )

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        tools = kwargs.get("tools", [])
        report_tool = next(
            (tool for tool in tools if tool["function"]["name"] == "DiagnosisSummary"),
            None,
        )
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        if report_tool:
            response = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "DiagnosisSummary",
                        "args": {
                            "hypotheses": [
                                "Local mock run; no semantic diagnosis was performed."
                            ],
                            "root_causes_by_view": {},
                            "keywords": [],
                            "evidence_ids": [],
                        },
                        "id": "mock-report",
                    }
                ],
                usage_metadata=usage,
            )
        else:
            response = AIMessage(
                content="Local mock run completed without tool evidence.",
                usage_metadata=usage,
            )
        return ChatResult(generations=[ChatGeneration(message=response)])


def create_diagnostic_models(llm_config, sampling):
    provider = llm_config["provider"].lower()
    if provider == "mock":
        return DiagnosticMockModel(), DiagnosticMockModel()
    providers = {"openai": "openai", "anthropic": "anthropic", "gemini": "google_genai"}
    if provider not in providers:
        raise ValueError(f"Unsupported diagnostic model provider: {provider}")
    environment = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "gemini": "GOOGLE_API_KEY",
    }
    api_key = llm_config.get("api_key") or os.getenv(environment[provider])

    def model(stage):
        options = {
            "max_tokens": sampling[stage]["max_tokens"],
            "max_retries": 0,
        }
        options["temperature"] = (
            sampling[stage]["temperature"]
            if llm_config.get("temperature_policy", "send") == "send"
            else None
        )
        if api_key:
            options["api_key"] = api_key
        if llm_config.get("base_url"):
            options["base_url"] = llm_config["base_url"]
        if llm_config.get("timeout") is not None:
            options["timeout"] = llm_config["timeout"]
        if provider == "openai" and llm_config.get("extra_body"):
            options["extra_body"] = llm_config["extra_body"]
        return init_chat_model(
            llm_config["model_name"], model_provider=providers[provider], **options
        )

    return model("diagnosis"), model("diagnosis_report")
