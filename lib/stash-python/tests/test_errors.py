"""Tests for error types."""

from stash.errors import (
    ConnectionError,
    DecryptionError,
    ForbiddenError,
    NotFoundError,
    ResponseError,
    StashError,
    UnauthorizedError,
)


class TestErrorHierarchy:
    def test_not_found_is_stash_error(self):
        assert issubclass(NotFoundError, StashError)

    def test_unauthorized_is_stash_error(self):
        assert issubclass(UnauthorizedError, StashError)

    def test_forbidden_is_stash_error(self):
        assert issubclass(ForbiddenError, StashError)

    def test_decryption_is_stash_error(self):
        assert issubclass(DecryptionError, StashError)

    def test_connection_is_stash_error(self):
        assert issubclass(ConnectionError, StashError)

    def test_response_is_stash_error(self):
        assert issubclass(ResponseError, StashError)


class TestResponseError:
    def test_status_code(self):
        err = ResponseError(500)
        assert err.status_code == 500

    def test_message(self):
        err = ResponseError(503)
        assert "HTTP 503" in str(err)
