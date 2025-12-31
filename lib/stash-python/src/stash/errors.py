"""Exception types for the Stash client library."""


class StashError(Exception):
    """Base exception for all Stash errors."""


class NotFoundError(StashError):
    """Raised when a key is not found (HTTP 404)."""


class UnauthorizedError(StashError):
    """Raised when authentication fails (HTTP 401)."""


class ForbiddenError(StashError):
    """Raised when access is denied (HTTP 403)."""


class DecryptionError(StashError):
    """Raised when ZK decryption fails (wrong key or corrupted data)."""


class ConnectionError(StashError):
    """Raised when connection to the server fails."""


class ResponseError(StashError):
    """Raised for unexpected HTTP status codes."""

    def __init__(self, status_code: int):
        self.status_code = status_code
        super().__init__(f"stash: HTTP {status_code}")
