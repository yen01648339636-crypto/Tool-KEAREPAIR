"""Extract structured vulnerability knowledge from verified source pairs."""

from utils.knowledge import DatasetError, parse_knowledge
from utils.telemetry import text_call
from utils.prompt_templates import load_template, validate_template


class MultiViewGenerator:
    VIEW_TYPES = ["data_flow", "control_flow"]

    def __init__(
        self,
        llm_interface,
        view_types=None,
        sampling=None,
        *,
        mode="standard",
        prompt_paths=None,
        extraction_prompt_paths=None,
    ):
        self.llm = llm_interface
        self.sampling = sampling or {}
        self.mode = mode
        self.VIEW_TYPES = list(self.VIEW_TYPES if view_types is None else view_types)
        allowed = {"data_flow", "control_flow"}
        if (
            mode not in {"standard", "extended"}
            or not self.VIEW_TYPES
            or len(set(self.VIEW_TYPES)) != len(self.VIEW_TYPES)
            or set(self.VIEW_TYPES) - allowed
        ):
            raise ValueError(
                "Unsupported or duplicate knowledge views for the selected mode"
            )
        prompt_paths, extraction_prompt_paths = (
            prompt_paths or {},
            extraction_prompt_paths or {},
        )
        self.prompts = {
            view: (
                load_template(prompt_paths[view])
                if view in prompt_paths
                else "Analyze the {view_type} vulnerability behavior in this code:\n{buggy_code}"
            )
            for view in self.VIEW_TYPES
        }
        self._patch_guided_prompts = {
            view: load_template(
                extraction_prompt_paths.get(
                    view, f"prompts/offline/patch_guided/{view}.txt"
                )
            )
            for view in self.VIEW_TYPES
        }

    def _get_patch_guided_prompts(self):
        return self._patch_guided_prompts

    def generate_single_view(self, buggy_code, view_type, patch=None):
        """Explicit blind analysis; the source-pair indexing path never falls back here."""
        if view_type not in self.VIEW_TYPES:
            raise ValueError(f"Unknown view: {view_type}")
        template = validate_template(self.prompts[view_type])
        return text_call(
            self.llm,
            template.format(
                buggy_code=buggy_code, patch=patch or "", view_type=view_type
            ),
            stage_name="blind:" + view_type,
            **self.sampling.get("blind", {"max_tokens": 1024, "temperature": 0.0}),
        )

    def customize_prompt(self, view_type, new_prompt):
        if view_type not in self.VIEW_TYPES:
            raise ValueError(f"Unknown view: {view_type}")
        self.prompts[view_type] = validate_template(new_prompt)

    def generate_single_view_with_patch(
        self, buggy_code, patch, view_type, *, fixed_code="", cve_description=""
    ):
        if view_type not in self.VIEW_TYPES:
            raise ValueError(f"Unknown view: {view_type}")
        if (
            not buggy_code.strip()
            or not fixed_code.strip()
            or not cve_description.strip()
        ):
            raise DatasetError(
                "Knowledge extraction requires a description and both vulnerable and repaired functions"
            )
        if buggy_code == fixed_code:
            raise DatasetError("The vulnerable and repaired functions must differ")
        template = validate_template(self._get_patch_guided_prompts()[view_type])
        prompt = template.format(
            buggy_code=buggy_code,
            fixed_code=fixed_code,
            patch=patch,
            cve_description=cve_description,
            view_type=view_type,
        )
        response = text_call(
            self.llm,
            prompt,
            "extraction:" + view_type,
            response_validator=lambda output: parse_knowledge(output, view_type),
            **self.sampling.get("extraction", {"max_tokens": 1024, "temperature": 0.0}),
        )
        return parse_knowledge(response, view_type)

    def extract_knowledge(self, sample, view_type):
        return self.generate_single_view_with_patch(
            sample["buggy_code"],
            sample["patch"],
            view_type,
            fixed_code=sample["fixed_code"],
            cve_description=sample["cve_description"],
        )
