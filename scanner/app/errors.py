"""Domain errors returned through stable scanner API responses."""


class PolicyError(ValueError):
    """Raised when a target or path violates the outbound request policy."""


class OutboundRequestError(RuntimeError):
    """Raised when a bounded outbound request cannot be completed."""


class ScannerExecutionError(RuntimeError):
    """Raised when the static analyzer fails or emits invalid output."""
