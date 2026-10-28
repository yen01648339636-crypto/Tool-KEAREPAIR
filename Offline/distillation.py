"""Abstract source-specific identifiers while retaining the complete knowledge record."""

import json

from utils.knowledge import parse_knowledge
from utils.telemetry import text_call
from utils.prompt_templates import load_template, validate_template
from utils.schemas import ContractError


class ViewDistillation:
    def __init__(self, llm_interface, sampling=None, *, prompt_path=None):
        self.llm = llm_interface
        self.sampling = sampling or {}
        self._prompts = {
            "without_patch": load_template(
                prompt_path or "prompts/offline/distill/without_patch.txt"
            )
        }

    def distill_without_patch(self, knowledge, view_type):
        extracted = parse_knowledge(knowledge, view_type)
        serialized = json.dumps(extracted.to_dict(), ensure_ascii=False)
        template = validate_template(self._prompts["without_patch"])
        prompt = template.format(
            view_type=view_type, knowledge_json=serialized, blind_view=serialized
        )
        def validate_response(response):
            abstracted = parse_knowledge(response, view_type)
            if extracted.risky_calls and not abstracted.risky_calls:
                raise ContractError("Abstraction discarded all extracted risky calls")
            for field in ("taint_flow", "control_branch"):
                before, after = getattr(extracted, field), getattr(abstracted, field)
                if (before is None) != (after is None) or (
                    before is not None and not after.strip()
                ):
                    raise ContractError(f"Abstraction must preserve the {field} field")
            return abstracted

        response = text_call(
            self.llm,
            prompt,
            "distillation:" + view_type,
            response_validator=validate_response,
            **self.sampling.get(
                "distillation", {"max_tokens": 512, "temperature": 0.0}
            ),
        )
        # A failed abstraction must not be replaced with unabstracted extraction text.
        return validate_response(response)
