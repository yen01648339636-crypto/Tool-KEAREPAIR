"""Render complete, auditable knowledge examples in ascending score order."""

from copy import deepcopy
import json
import math

from utils.knowledge import parse_knowledge


def render_exemplars(exemplars, limit):
    if type(limit) is not int or limit < 1:
        raise ValueError("Exemplar limit must be positive")
    ids = [item["sample_id"] for item in exemplars]
    if any(not isinstance(value, str) or not value for value in ids) or len(
        set(ids)
    ) != len(ids):
        raise ValueError("Exemplars require unique stable IDs")
    for item in exemplars:
        if type(item["rerank_score"]) not in (int, float) or not math.isfinite(
            item["rerank_score"]
        ):
            raise ValueError("Exemplars require finite reranking scores")
    chosen = sorted(
        exemplars, key=lambda item: (-item["rerank_score"], item["sample_id"])
    )[:limit]
    chosen.sort(key=lambda item: (item["rerank_score"], item["sample_id"]))
    rendered = []
    for order, item in enumerate(chosen, 1):
        for key in ("buggy_code", "fixed_code", "patch"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"Exemplar {item['sample_id']} lacks {key}")
        if not isinstance(item.get("views"), dict) or not item["views"]:
            raise ValueError("Exemplar requires structured knowledge views")
        views = {
            view: {
                name: parse_knowledge(payload[name], view).to_dict()
                for name in ("extracted_knowledge", "abstracted_knowledge")
            }
            for view, payload in sorted(item["views"].items())
        }
        text = f"Example {order} (sample_id={item['sample_id']}, score={item['rerank_score']:.8f}):\n"
        for view, knowledge in views.items():
            text += (
                f"\n[{view}: root cause, risky calls, flow/branch, fixing strategy]\n"
                + json.dumps(knowledge, ensure_ascii=False, indent=2)
                + "\n"
            )
        text += "\n[Vulnerable code — complete]\n" + item["buggy_code"]
        text += "\n\n[Repaired code — complete]\n" + item["fixed_code"]
        text += "\n\n[Unified diff — complete]\n" + item["patch"]
        rendered.append(
            {
                **deepcopy(item),
                "views": views,
                "render_order": order,
                "clipping": {
                    "strategy": "full_example",
                    "truncated": False,
                    "buggy_code_chars": len(item["buggy_code"]),
                    "fixed_code_chars": len(item["fixed_code"]),
                    "patch_chars": len(item["patch"]),
                },
                "rendered_text": text,
            }
        )
    return "\n\n".join(item["rendered_text"] for item in rendered), rendered
