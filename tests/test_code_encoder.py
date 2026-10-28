"""Exercise the encoding protocol with tiny local tensors and a fake backbone."""

from contextlib import nullcontext
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np

from models.code_encoder import CodeEncoder, DEFAULT_REVISION


class Tensor:
    def __init__(self, value):
        self.value = np.asarray(value)

    def to(self, *args):
        return self

    def cpu(self):
        return self

    def float(self):
        return Tensor(self.value.astype(np.float32))

    def unsqueeze(self, axis):
        return Tensor(np.expand_dims(self.value, axis))

    def sum(self, dim):
        return Tensor(self.value.sum(axis=dim))

    def clamp(self, min):
        return Tensor(np.maximum(self.value, min))

    def numpy(self):
        return self.value

    def tolist(self):
        return self.value.tolist()

    def __mul__(self, other):
        return Tensor(self.value * other.value)

    def __truediv__(self, other):
        return Tensor(self.value / other.value)


class Tokenizer:
    pad_token_id = None
    eos_token = "</s>"

    def __call__(self, texts, **kwargs):
        if isinstance(texts, str):
            return {"input_ids": [1] + list(range(2, len(texts.split()) + 2))}
        ids = [self(text)["input_ids"][: kwargs["max_length"]] for text in texts]
        length = max(map(len, ids))
        return dict(
            input_ids=Tensor([row + [0] * (length - len(row)) for row in ids]),
            attention_mask=Tensor(
                [[1] * len(row) + [0] * (length - len(row)) for row in ids]
            ),
        )


class Backbone:
    config = SimpleNamespace(
        model_type="llama", max_position_embeddings=4096, hidden_size=2
    )

    def to(self, device):
        self.device = device
        return self

    def eval(self):
        return self

    def __call__(self, input_ids, attention_mask, use_cache):
        assert use_cache is False
        # Deliberately huge padding hidden states to expose unmasked pooling.
        values = np.where(attention_mask.value, input_ids.value, 9999)
        return SimpleNamespace(
            last_hidden_state=Tensor(np.stack([values, np.ones_like(values)], axis=-1))
        )


class TestCodeEncoder(unittest.TestCase):
    def modules(self):
        torch, transformers = ModuleType("torch"), ModuleType("transformers")
        torch.float32, torch.float16, torch.bfloat16 = "float32", "float16", "bfloat16"
        torch.inference_mode = nullcontext
        calls = []
        tokenizer, model = Tokenizer(), Backbone()

        def load(value):
            def loader(name, **kwargs):
                calls.append((name, kwargs))
                return value

            return loader

        transformers.AutoTokenizer = SimpleNamespace(from_pretrained=load(tokenizer))
        transformers.AutoModel = SimpleNamespace(from_pretrained=load(model))
        return {"torch": torch, "transformers": transformers}, calls, tokenizer, model

    def test_pinned_loading_mean_pooling_normalization_padding_and_truncation(self):
        modules, calls, tokenizer, _ = self.modules()
        with patch.dict("sys.modules", modules):
            encoder = CodeEncoder(max_length=4, batch_size=2, local_files_only=True)
            values = encoder.encode(["one", "one two three four five"])
        expected = np.asarray([[1.5, 1.0], [2.5, 1.0]])
        expected /= np.linalg.norm(expected, axis=1, keepdims=True)
        np.testing.assert_allclose(values, expected, rtol=1e-6)
        self.assertEqual(
            encoder.last_encoding_metadata,
            [
                dict(
                    input_tokens=2,
                    used_tokens=2,
                    truncated=False,
                    strategy="right_token_truncation",
                    max_length=4,
                ),
                dict(
                    input_tokens=6,
                    used_tokens=4,
                    truncated=True,
                    strategy="right_token_truncation",
                    max_length=4,
                ),
            ],
        )
        self.assertTrue(
            all(
                options["revision"] == DEFAULT_REVISION
                and options["local_files_only"]
                and not options["trust_remote_code"]
                for _, options in calls
            )
        )
        self.assertEqual(calls[1][1]["torch_dtype"], "float32")
        self.assertTrue(calls[0][1]["use_fast"])
        self.assertTrue(calls[0][1]["add_bos_token"])
        self.assertFalse(calls[0][1]["add_eos_token"])
        self.assertEqual(tokenizer.pad_token, tokenizer.eos_token)
        self.assertEqual(tokenizer.padding_side, "right")
        self.assertEqual(tokenizer.truncation_side, "right")

    def test_batch_size_does_not_change_embeddings_and_empty_input_resets_metadata(
        self,
    ):
        modules, _, _, _ = self.modules()
        with patch.dict("sys.modules", modules):
            first = CodeEncoder(batch_size=1).encode(["short", "a longer fragment"])
            encoder = CodeEncoder(batch_size=2)
            second = encoder.encode(["short", "a longer fragment"])
            self.assertEqual(encoder.encode([]).shape, (0, 2))
            self.assertEqual(encoder.last_encoding_metadata, [])
            with self.assertRaises(ValueError):
                encoder.encode([""])
        np.testing.assert_allclose(first, second)

    def test_protocol_and_backbone_limits_are_checked(self):
        for kwargs in (
            dict(revision="main"),
            dict(pooling="cls"),
            dict(truncation_side="left"),
            dict(dtype="int8"),
            dict(batch_size=0),
        ):
            with self.assertRaises(ValueError):
                CodeEncoder(**kwargs)
        modules, _, _, _ = self.modules()
        with patch.dict("sys.modules", modules), self.assertRaises(ValueError):
            CodeEncoder(max_length=4097)

    def test_loading_failure_propagates_without_random_or_hash_fallback(self):
        modules, _, _, _ = self.modules()

        def fail(*args, **kwargs):
            raise OSError("missing local weights")

        modules["transformers"].AutoModel.from_pretrained = fail
        with patch.dict("sys.modules", modules), self.assertRaises(OSError):
            CodeEncoder(local_files_only=True)
