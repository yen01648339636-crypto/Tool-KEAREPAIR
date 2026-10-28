"""Shared model failures without importing model backends."""


class LLMError(RuntimeError):
    """A model request failed."""


class LLMAuthError(LLMError):
    """Authentication or quota prevents further requests."""


class LLMConnectionError(LLMError):
    """No API connection could be established; preserve work and stop advancing."""

    reason = "network_unavailable"

    def __init__(self, message, *, attempts, causes):
        super().__init__(message)
        self.attempts = attempts
        self.causes = causes


class LLMRetryExhaustedError(LLMError):
    """A transient request failure persisted through every allowed attempt."""

    reason = "transient_request_retries_exhausted"

    def __init__(self, message, *, attempts, status_code=None):
        super().__init__(message)
        self.attempts = attempts
        self.status_code = status_code


class LLMOutputValidationError(LLMRetryExhaustedError):
    """Generated knowledge remained invalid after the shared request budget."""

    reason = "knowledge_validation_retries_exhausted"
