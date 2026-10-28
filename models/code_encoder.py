"""Pinned CodeLlama last-layer embeddings for vulnerable-code comparison."""

import re
import numpy as np


DEFAULT_MODEL = "codellama/CodeLlama-7b-hf"
DEFAULT_REVISION = "6c284d1468fe6c413cf56183e69b194dcfa27fe6"


class CodeEncoder:
    def __init__(
        self,
        model_name=DEFAULT_MODEL,
        revision=DEFAULT_REVISION,
        *,
        device="cpu",
        max_length=2048,
        batch_size=1,
        pooling="masked_mean",
        truncation_side="right",
        dtype="float32",
        local_files_only=False
    ):
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError(
                "Code encoder revision must be an immutable 40-character commit SHA"
            )
        if pooling != "masked_mean" or truncation_side != "right":
            raise ValueError(
                "Supported encoding protocol: masked_mean pooling, right token truncation"
            )
        if (
            type(max_length) is not int
            or max_length < 2
            or type(batch_size) is not int
            or batch_size < 1
        ):
            raise ValueError(
                "Code encoder lengths and batch size must be positive (max_length >= 2)"
            )
        if dtype not in {"float32", "float16", "bfloat16"}:
            raise ValueError("Unsupported code encoder dtype")
        if (
            not isinstance(model_name, str)
            or not model_name.strip()
            or type(local_files_only) is not bool
        ):
            raise ValueError(
                "A code model name and boolean local_files_only are required"
            )
        import torch
        from transformers import AutoModel, AutoTokenizer

        self.torch = torch
        self.device, self.max_length, self.batch_size = device, max_length, batch_size
        self.protocol = dict(
            model_name=model_name,
            revision=revision,
            pooling=pooling,
            max_length=max_length,
            truncation_side=truncation_side,
            dtype=dtype,
            batch_size=batch_size,
            add_special_tokens=True,
            use_fast=True,
            add_bos_token=True,
            add_eos_token=False,
            padding_side="right",
            normalization="l2",
            layer="last_hidden_state",
        )
        options = dict(
            revision=revision,
            local_files_only=local_files_only,
            trust_remote_code=False,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            use_fast=True,
            add_bos_token=True,
            add_eos_token=False,
            **options
        )
        self.tokenizer.padding_side = "right"
        self.tokenizer.truncation_side = truncation_side
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.model = (
            AutoModel.from_pretrained(
                model_name, torch_dtype=getattr(torch, dtype), **options
            )
            .to(device)
            .eval()
        )
        if self.model.config.model_type != "llama":
            raise ValueError("Code encoder requires a CodeLlama/Llama backbone")
        if max_length > self.model.config.max_position_embeddings:
            raise ValueError("Configured code length exceeds model position limit")
        self.dimension = self.model.config.hidden_size
        self.last_encoding_metadata = []

    def encode(self, codes):
        codes = [codes] if isinstance(codes, str) else codes
        if not isinstance(codes, list) or any(
            not isinstance(code, str) or not code.strip() for code in codes
        ):
            raise ValueError("Code inputs must be nonempty strings")
        self.last_encoding_metadata = []
        vectors = []
        for start in range(0, len(codes), self.batch_size):
            batch = codes[start : start + self.batch_size]
            lengths = [
                len(
                    self.tokenizer(code, add_special_tokens=True, truncation=False)[
                        "input_ids"
                    ]
                )
                for code in batch
            ]
            inputs = self.tokenizer(
                batch,
                add_special_tokens=True,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=self.max_length,
            )
            inputs = {key: value.to(self.device) for key, value in inputs.items()}
            with self.torch.inference_mode():
                hidden = self.model(**inputs, use_cache=False).last_hidden_state
                mask = inputs["attention_mask"].unsqueeze(-1).to(self.torch.float32)
                pooled = (hidden.float() * mask).sum(dim=1) / mask.sum(dim=1).clamp(
                    min=1
                )
                vectors.append(pooled.cpu().numpy())
            used = inputs["attention_mask"].sum(dim=1).cpu().tolist()
            self.last_encoding_metadata.extend(
                {
                    "input_tokens": total,
                    "used_tokens": count,
                    "truncated": total > count,
                    "strategy": "right_token_truncation",
                    "max_length": self.max_length,
                }
                for total, count in zip(lengths, used)
            )
        values = (
            np.concatenate(vectors, axis=0)
            if vectors
            else np.empty((0, self.dimension), dtype=np.float32)
        )
        norms = np.linalg.norm(values, axis=1, keepdims=True)
        if (
            values.shape != (len(codes), self.dimension)
            or not np.isfinite(values).all()
            or np.any(norms == 0)
        ):
            raise ValueError("Code encoder returned invalid or zero embeddings")
        return values / norms
