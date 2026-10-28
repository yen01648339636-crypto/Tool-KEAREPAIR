"""统一的 LLM 接口封装（支持 OpenAI/Anthropic/Gemini/Mock）

API 调用说明：
=============
OpenAI 接口通过官方 SDK 的 Chat Completions 发起 HTTP 请求：
  - 请求格式：POST https://api.openai.com/v1/chat/completions
  - 请求头：Authorization: Bearer sk-你的API密钥
  - 请求体：{"model":"gpt-4o-mini","messages":[...],"temperature":...}
  - 响应：{"choices":[{"message":{"content":"..."}}]}

Google Gemini 接口通过官方 google-genai SDK 调用：
  - 使用 GOOGLE_API_KEY 或配置文件中的 models.llm.api_key 进行认证
  - 支持 generate_content() 和多轮对话 chats.create()

API Key 来源：
  1. 优先使用初始化时传入的 api_key 参数
  2. OpenAI: 从环境变量 OPENAI_API_KEY 读取
  3. Anthropic: 从环境变量 ANTHROPIC_API_KEY 读取
  4. Gemini: 从环境变量 GOOGLE_API_KEY 读取
"""

from typing import Callable, List, Optional
from loguru import logger
import os
import re
import json
import time
import random
from uuid import uuid4
from utils.telemetry import begin_call, finish_call, json_value
from utils.llm_errors import LLMError, LLMAuthError, LLMConnectionError, LLMRetryExhaustedError, LLMOutputValidationError
from utils.schemas import ContractError


class LLMInterface:
    """统一的文本模型接口，包含请求尝试记录。"""

    records_requests = True
    validates_responses = True

    def __init__(
        self,
        provider: str = "openai",
        model_name: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        extra_body: Optional[dict] = None,
        temperature_policy: str = "send",
        token_limit_parameter: str = "max_tokens",
    ):
        """
        初始化 LLM 接口

        Args:
            provider: 提供商 (openai, anthropic, mock)
            model_name: 模型名称
            api_key: API 密钥（None 时从环境变量读取）
            base_url: API 端点 URL（可选）
                - OpenAI 默认: https://api.openai.com/v1
                - Azure OpenAI: https://{resource}.openai.azure.com
                - 自定义代理/兼容服务: 你的自定义 URL
            temperature: 采样温度
            max_tokens: 最大生成 token 数
        """
        self.provider = provider.lower()
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.base_url = base_url
        self.extra_body = dict(extra_body or {})
        if set(self.extra_body) & {
            "temperature",
            "max_tokens",
            "max_output_tokens",
            "max_completion_tokens",
        }:
            raise ValueError("extra_body cannot override stage sampling parameters")
        if temperature_policy not in {"send", "omit"}:
            raise ValueError("temperature_policy must be send or omit")
        self.temperature_policy = temperature_policy
        if token_limit_parameter not in {"max_tokens", "max_completion_tokens"}:
            raise ValueError("Unsupported output-token parameter")
        self.token_limit_parameter = token_limit_parameter
        self.last_call_parameters = {}
        self.call_records = []
        self.request_attempt_count = 0
        self.last_response_metadata = {}

        # 从环境变量获取 API Key（如果没有显式传入）
        if api_key is None:
            if self.provider == "openai":
                api_key = os.getenv("OPENAI_API_KEY")
            elif self.provider == "anthropic":
                api_key = os.getenv("ANTHROPIC_API_KEY")
            elif self.provider == "gemini":
                api_key = os.getenv("GOOGLE_API_KEY")

        self.api_key = api_key
        self.client = self._initialize_client()

    def _is_auth_error(self, exc: Exception, msg: str) -> bool:
        status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
        m = (msg or "").lower()
        # Some gateways return non-JSON (HTML) or wrap errors in custom messages, so rely on strings too.
        auth_markers = [
            "invalid_api_key",
            "incorrect api key",
            "invalid token",
            "unauthorized",
            "无效的令牌",
            "令牌无效",
            "api key 无效",
            "api key 无效或过期",
            "额度已用尽",
            "quota",
        ]
        return status in (401, 403) or any(k in m for k in auth_markers)

    def _is_connection_error(self, exc):
        if getattr(exc, "status_code", None) or getattr(exc, "status", None):
            return False  # A gateway HTTP error is handled by the batch-skip policy.
        names = {
            "APIConnectionError", "APITimeoutError", "ConnectError", "ConnectTimeout",
            "ReadTimeout", "WriteTimeout", "ReadError", "WriteError", "ProxyError",
            "PoolTimeout", "RemoteProtocolError", "TimeoutError", "ConnectionError",
            "ConnectionResetError", "ConnectionRefusedError", "gaierror",
        }
        seen = set()
        current = exc
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            if type(current).__name__ in names:
                return True
            current = current.__cause__ or current.__context__
        message = str(exc).lower()
        return any(part in message for part in (
            "connection error", "connection refused", "connection reset",
            "connection aborted", "timed out", "connection timeout",
        ))

    def _connection_causes(self, exc):
        causes, seen = [], set()
        while exc is not None and id(exc) not in seen:
            seen.add(id(exc))
            message = str(exc)
            if self.api_key:
                message = message.replace(self.api_key, "[REDACTED]")
            message = re.sub(r"sk-[A-Za-z0-9_-]+", "[REDACTED]", message)
            message = re.sub(r"(?i)((?:https?|socks5h?)://)[^\s/@]+@", r"\1[REDACTED]@", message)
            causes.append({"type": type(exc).__name__, "message": message[:1000]})
            exc = exc.__cause__ or exc.__context__
        return causes

    def _is_retryable_error(self, exc: Exception, msg: str) -> bool:
        status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
        m = (msg or "").lower()
        # If it's clearly an auth/quota problem, don't retry.
        if self._is_auth_error(exc, msg):
            return False
        # Cloudflare/proxy HTML error pages, common in custom gateways
        if (
            "<!doctype html" in m
            or "cloudflare" in m
            or "error 524" in m
            or " 524" in m
        ):
            return True
        # Typical transient HTTP codes
        if status in (408, 409, 425, 429, 500, 502, 503, 504, 524):
            return True
        # Network/timeout strings
        transient = [
            "timeout",
            "timed out",
            "connection error",
            "connection reset",
            "connection aborted",
            "remote protocol error",
            "server disconnected",
            "eof",
            "temporarily unavailable",
        ]
        return any(t in m for t in transient)

    def _initialize_client(self):
        """初始化 provider 对应的客户端"""
        if self.provider == "openai":
            try:
                from openai import OpenAI

                # ★ 这里创建 OpenAI 客户端，后续所有请求都通过它发送
                # 如果指定了 base_url，使用自定义端点；否则使用默认端点
                client_kwargs = {"api_key": self.api_key, "max_retries": 0}
                if self.base_url:
                    client_kwargs["base_url"] = self.base_url
                    logger.info(f"使用自定义 OpenAI 端点: {self.base_url}")
                client = OpenAI(**client_kwargs)
                self._sanitize_openai_header_builder(client)
                return client
            except ImportError:
                logger.error("openai 包未安装。请运行: pip install openai")
                return None

        elif self.provider == "anthropic":
            try:
                from anthropic import Anthropic

                # Anthropic 也支持自定义 base_url
                client_kwargs = {"api_key": self.api_key, "max_retries": 0}
                if self.base_url:
                    client_kwargs["base_url"] = self.base_url
                    logger.info(f"使用自定义 Anthropic 端点: {self.base_url}")
                return Anthropic(**client_kwargs)
            except ImportError:
                logger.error("anthropic 包未安装。请运行: pip install anthropic")
                return None

        elif self.provider == "gemini":
            try:
                from google import genai

                from google.genai import types

                client = genai.Client(
                    api_key=self.api_key,
                    http_options=types.HttpOptions(
                        base_url=self.base_url or None,
                        retry_options=types.HttpRetryOptions(attempts=1),
                    ),
                )
                logger.info(f"使用 Google Gemini 原生 SDK，模型: {self.model_name}")
                return client
            except ImportError:
                logger.error("google-genai 包未安装。请运行: pip install google-genai")
                return None

        elif self.provider == "mock":
            # Mock 模式：用于离线测试，不发起真实 API 请求
            return None

        else:
            raise ValueError(f"未知的 provider: {self.provider}")

    def _sanitize_openai_header_builder(self, client) -> None:
        """Wrap OpenAI SDK header sources to drop Omit/non-ASCII header values.

        Some SDK/environment combinations may leak sentinel objects or non-ASCII
        values into request headers, and httpx then raises UnicodeEncodeError
        while normalizing headers. We defensively sanitize the final header map
        before it reaches `httpx.Headers(...)`.
        """
        if client is None or not hasattr(client, "_build_headers"):
            return

        original_build_headers = client._build_headers
        client_cls = type(client)
        original_default_headers_prop = getattr(client_cls, "default_headers", None)
        original_default_headers_getter = (
            original_default_headers_prop.fget
            if isinstance(original_default_headers_prop, property)
            else None
        )

        def _sanitize_mapping(mapping):
            sanitized = {}
            for key, value in mapping.items():
                if value is None:
                    continue
                text = value if isinstance(value, str) else str(value)
                # Skip OpenAI's Omit sentinel placeholders entirely.
                if text.startswith("<openai.Omit object at "):
                    continue
                try:
                    text.encode("ascii")
                except UnicodeEncodeError:
                    logger.warning(f"跳过非 ASCII 请求头: {key}={text!r}")
                    continue
                sanitized[key] = text
            return sanitized

        def _wrapped_build_headers(options, *, retries_taken=0):
            custom_headers = getattr(options, "headers", None)
            if isinstance(custom_headers, dict):
                options.headers = _sanitize_mapping(custom_headers)
            return original_build_headers(options, retries_taken=retries_taken)

        # Replace the class property so OpenAI SDK never passes problematic
        # default header values into httpx.Headers(...).
        if original_default_headers_getter and not getattr(
            client_cls, "_mvbdsr_sanitized_default_headers", False
        ):

            def _sanitized_default_headers(instance):
                raw = original_default_headers_getter(instance)
                return _sanitize_mapping(raw)

            client_cls.default_headers = property(_sanitized_default_headers)
            client_cls._mvbdsr_sanitized_default_headers = True

        client._build_headers = _wrapped_build_headers

    def effective_sampling(self, max_tokens=None, temperature=None):
        options = {"max_tokens": self.max_tokens if max_tokens is None else max_tokens}
        if self.temperature_policy == "send":
            options["temperature"] = (
                self.temperature if temperature is None else temperature
            )
        return options

    def generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        stop: Optional[List[str]] = None,
        response_validator: Optional[Callable[[str], object]] = None,
    ) -> str:
        """
        生成文本（核心调用入口）

        ★★★ 这是整个框架调用 LLM 的统一入口 ★★★
        离线索引、查询与修复使用此入口；诊断的原生聊天调用由 LangChain 回调记录。

        Args:
            prompt: 输入 prompt
            max_tokens: 最大 token 数（None 时使用默认值）
            temperature: 温度（None 时使用默认值）
            stop: 停止序列
            response_validator: 本地输出校验；ContractError 与 API 错误共用尝试次数

        Returns:
            生成的文本

        Raises:
            LLMAuthError: API Key 无效/过期
            LLMError: 其他 LLM 调用错误
        """
        effective = self.effective_sampling(max_tokens, temperature)
        self.last_call_parameters = {
            "model": self.model_name,
            "provider": self.provider,
            "temperature_policy": self.temperature_policy,
            **effective,
        }
        if self.provider == "openai":
            self.last_call_parameters["wire_token_limit_parameter"] = (
                self.token_limit_parameter
            )
        max_tokens = effective["max_tokens"]
        temperature = effective.get("temperature")

        max_attempts = max(1, int(os.getenv("LLM_MAX_RETRIES", "3")))
        base_delay = float(os.getenv("LLM_RETRY_BASE_DELAY", "1.5"))
        group_id = uuid4().hex
        for attempt in range(max_attempts):
            record = begin_call(
                self.model_name,
                self.provider,
                {
                    **self.last_call_parameters,
                    "prompt": prompt,
                    "stop": stop,
                    "extra_body": self.extra_body,
                },
                simulation=self.provider == "mock",
                retry_index=attempt,
                request_group_id=group_id,
            )
            self.call_records.append(record)
            self.request_attempt_count += 1
            # Complete journals live on disk; bound retained prompts during large builds.
            if len(self.call_records) > 256:
                del self.call_records[0]
            self.last_response_metadata = {}
            response = None
            validating_response = False
            started = time.monotonic()
            try:
                if self.provider == "mock":
                    response = self._generate_mock(prompt)
                elif self.provider == "openai":
                    response = self._generate_openai(
                        prompt, max_tokens, temperature, stop
                    )
                elif self.provider == "anthropic":
                    response = self._generate_anthropic(
                        prompt, max_tokens, temperature, stop
                    )
                elif self.provider == "gemini":
                    response = self._generate_gemini(
                        prompt, max_tokens, temperature, stop
                    )
                else:
                    raise ValueError(f"Unknown provider: {self.provider}")
                if response_validator is not None:
                    validating_response = True
                    response_validator(response)
                    validating_response = False
            except Exception as exc:
                # Failed attempts are journaled independently before any retry/backoff.
                connection_failure = not validating_response and self._is_connection_error(exc)
                if connection_failure:
                    record["connection_causes"] = self._connection_causes(exc)
                finish_call(
                    record,
                    started,
                    error=(RuntimeError(record["connection_causes"][0]["message"])
                           if connection_failure else exc),
                    raw_usage=self.last_response_metadata.get("usage"),
                    cost=self.last_response_metadata.get("cost"),
                    response=response,
                    response_metadata=self.last_response_metadata.get("response"),
                )
                message = str(exc)
                if validating_response and isinstance(exc, ContractError):
                    if attempt + 1 < max_attempts:
                        continue
                    raise LLMOutputValidationError(
                        f"LLM output validation failed after {max_attempts} attempts: {message}",
                        attempts=max_attempts,
                    ) from exc
                if self._is_auth_error(exc, message):
                    raise LLMAuthError(f"API authentication failed: {message}") from exc
                if connection_failure or self._is_retryable_error(exc, message):
                    if attempt + 1 < max_attempts:
                        time.sleep(base_delay * (2**attempt) + random.uniform(0, 0.6))
                        continue
                    if connection_failure:
                        causes = self._connection_causes(exc)
                        chain = " -> ".join(cause["type"] for cause in causes)
                        raise LLMConnectionError(
                            f"API connection unavailable after {max_attempts} attempts ({chain}): {causes[0]['message']}",
                            attempts=max_attempts, causes=causes,
                        ) from exc
                    raise LLMRetryExhaustedError(
                        f"LLM generation failed after {max_attempts} attempts: {message}",
                        attempts=max_attempts,
                        status_code=getattr(exc, "status_code", None),
                    ) from exc
                raise LLMError(f"LLM generation failed: {message}") from exc
            finish_call(
                record,
                started,
                raw_usage=self.last_response_metadata.get("usage"),
                cost=self.last_response_metadata.get("cost"),
                response=response,
                response_metadata=self.last_response_metadata.get("response"),
            )
            return response

    def _capture_response(self, response, usage_name="usage"):
        data = json_value(response)
        usage = getattr(response, usage_name, None)
        if usage is None and isinstance(data, dict):
            usage = data.get(usage_name)
        cost = data.get("cost") if isinstance(data, dict) else None
        self.last_response_metadata = {
            "usage": json_value(usage),
            "cost": cost,
            "response": (
                {
                    key: data.get(key)
                    for key in (
                        "id",
                        "model",
                        "model_version",
                        "response_id",
                        "system_fingerprint",
                    )
                    if key in data
                }
                if isinstance(data, dict)
                else None
            ),
        }

    def _generate_openai(
        self,
        prompt: str,
        max_tokens: int,
        temperature: float,
        stop: Optional[List[str]],
    ) -> str:
        """
        使用 OpenAI API 生成

        ★ 实际 HTTP 请求在这里发出 ★
        调用链：self.client.chat.completions.create()
                → OpenAI SDK 内部
                → POST https://api.openai.com/v1/chat/completions
                → Headers: {"Authorization": "Bearer sk-..."}
                → Body: {"model":"...","messages":[...],"temperature":...}
        """
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
            **{self.token_limit_parameter: max_tokens},
            **({"temperature": temperature} if temperature is not None else {}),
            stop=stop,
            **({"extra_body": self.extra_body} if self.extra_body else {}),
        )
        self._capture_response(response)
        return response.choices[0].message.content

    def _generate_anthropic(
        self,
        prompt: str,
        max_tokens: int,
        temperature: float,
        stop: Optional[List[str]],
    ) -> str:
        """使用 Anthropic API 生成"""
        response = self.client.messages.create(
            model=self.model_name,
            max_tokens=max_tokens,
            **({"temperature": temperature} if temperature is not None else {}),
            messages=[{"role": "user", "content": prompt}],
            stop_sequences=stop,
        )
        self._capture_response(response)
        return "".join(
            part.text
            for part in response.content
            if getattr(part, "type", "text") == "text"
        )

    def _generate_gemini(
        self,
        prompt: str,
        max_tokens: int,
        temperature: float,
        stop: Optional[List[str]],
    ) -> str:
        """
        使用 Google Gemini 原生 SDK 生成

        ★ 实际 HTTP 请求在这里发出 ★
        调用链：self.client.models.generate_content()
                → google-genai SDK 内部
                → POST https://generativelanguage.googleapis.com/v1beta/models/...
                → Headers: {"x-goog-api-key": "AIza..."}
        """
        from google import genai
        from google.genai import types

        config_kwargs = {
            "max_output_tokens": max_tokens,
            **({"temperature": temperature} if temperature is not None else {}),
        }
        if stop:
            config_kwargs["stop_sequences"] = stop

        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=types.GenerateContentConfig(**config_kwargs),
        )
        self._capture_response(response, "usage_metadata")
        return response.text

    def _extract_view_type(self, prompt: str) -> str:
        """从 prompt 中提取视角类型（用于 mock 模式）"""
        m = re.search(r"【View Type】\s*\n\s*([a-zA-Z_]+)\s*", prompt)
        if m:
            return m.group(1).strip()
        m = re.search(r"View Type:\s*([a-zA-Z_]+)", prompt)
        if m:
            return m.group(1).strip()
        m = re.search(r'"view_type"\s*:\s*"([^"]+)"', prompt)
        if m:
            return m.group(1).strip()
        m = re.search(r"The view is ([a-zA-Z_]+)", prompt)
        if m:
            return m.group(1)
        return "unknown"

    def _generate_mock(self, prompt: str) -> str:
        """
        Mock 模式：生成符合格式的假数据（用于离线测试）
        不发起任何网络请求，返回结构正确的测试数据
        """
        if prompt.startswith("Analyze the vulnerable source in"):
            views = [
                view
                for view in ("data_flow", "control_flow")
                if view in prompt.split("[Original-file source lines", 1)[0]
            ]
            return json.dumps(
                {
                    "root_causes_by_view": {
                        view: "Unverified root-cause hypothesis from an explicit local mock simulation."
                        for view in views
                    },
                    "hypotheses": [
                        "Local mock simulation; no semantic analysis was performed."
                    ],
                    "keywords": [],
                    "limitations": ["Mock output is not a vulnerability finding."],
                }
            )
        if prompt.startswith("Generate a reusable"):
            view = "control_flow" if "reusable control_flow" in prompt else "data_flow"
            return json.dumps(
                {"view": view, "root_cause": "Unverified mock vulnerability mechanism"}
            )

        view_type = self._extract_view_type(prompt)

        if "fixing_strategy" in prompt and "risky_calls" in prompt:
            result = {
                "view_type": view_type,
                "root_cause": "Mock knowledge: an unchecked input value reaches an unsafe operation.",
                "risky_calls": ["Mock operation: input controls an unsafe use"],
                "fixing_strategy": "Mock knowledge: validate the input before the unsafe operation.",
            }
            if view_type == "data_flow":
                result["taint_flow"] = "Mock input -> unchecked value -> unsafe use"
            elif view_type == "control_flow":
                result["control_branch"] = (
                    "Mock path reaches an unsafe use without a guard"
                )
            return json.dumps(result)

        wants_distill = (
            ('"view_type"' in prompt)
            and ("fix_hints" in prompt)
            and ("constraints" in prompt)
        )

        if wants_distill:
            # 蒸馏请求
            return json.dumps(
                {
                    "view_type": view_type,
                    "root_cause": "Mock 模式：可能缺少边界检查/空指针检查或输入验证导致漏洞。",
                    "signals": ["lack_of_validation", "unsafe_api_or_boundaries"],
                    "entities": {"vars": [], "funcs": [], "apis": []},
                    "constraints": ["添加必要的输入校验/边界检查"],
                    "fix_hints": [
                        "在关键分支前增加判空/范围检查",
                        "确保长度/索引不越界",
                    ],
                },
                ensure_ascii=False,
            )

        # 盲视生成请求
        return (
            f"root_cause: Mock 模式（{view_type}）：疑似缺少校验/边界检查导致不安全数据传播或错误分支。\n"
            f"evidence: 见 Buggy Code 中与输入处理/索引/指针相关的语句。\n"
            f"constraints: 修复需保持原有语义，增加必要检查。\n"
            f"fix_hints: 1) 判空/范围检查 2) 修正条件分支 3) 处理返回值/错误码。\n"
        )

    def count_tokens(self, text: str) -> int:
        """
        估算 token 数量（简单估算，生产环境应使用 tiktoken）

        Args:
            text: 输入文本

        Returns:
            估算的 token 数
        """
        return len(text) // 4

    def batch_generate(
        self,
        prompts: List[str],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> List[str]:
        """
        批量生成

        Args:
            prompts: prompt 列表
            max_tokens: 最大 token 数
            temperature: 温度

        Returns:
            生成文本列表
        """
        responses = []
        for i, prompt in enumerate(prompts):
            logger.debug(f"生成 {i+1}/{len(prompts)}")
            response = self.generate(prompt, max_tokens, temperature)
            responses.append(response)
        return responses
