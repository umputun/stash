"""Tests for the Stash HTTP client."""

import json
from unittest.mock import MagicMock, patch

import pytest

from stash import Client
from stash.errors import ForbiddenError, NotFoundError, ResponseError, UnauthorizedError


class TestClientInit:
    def test_empty_base_url(self):
        with pytest.raises(ValueError, match="base_url is required"):
            Client("")

    def test_base_url_normalization(self):
        client = Client("http://localhost:8080/")
        assert client._base_url == "http://localhost:8080"

    def test_zk_key_too_short(self):
        with pytest.raises(ValueError, match="at least 16"):
            Client("http://localhost:8080", zk_key="short")

    def test_zk_key_valid(self):
        client = Client("http://localhost:8080", zk_key="a" * 16)
        assert client._zk is not None


class TestClientGet:
    def test_get_success(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"test value"

        with patch.object(client._pool, "request", return_value=mock_resp):
            result = client.get("test/key")
            assert result == "test value"

    def test_get_not_found(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 404

        with patch.object(client._pool, "request", return_value=mock_resp), pytest.raises(NotFoundError):
            client.get("missing/key")

    def test_get_unauthorized(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 401

        with patch.object(client._pool, "request", return_value=mock_resp), pytest.raises(UnauthorizedError):
            client.get("test/key")

    def test_get_forbidden(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 403

        with patch.object(client._pool, "request", return_value=mock_resp), pytest.raises(ForbiddenError):
            client.get("test/key")

    def test_get_empty_key(self):
        client = Client("http://localhost:8080")
        with pytest.raises(ValueError, match="key is required"):
            client.get("")

    def test_get_or_default_exists(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"value"

        with patch.object(client._pool, "request", return_value=mock_resp):
            result = client.get_or_default("key", "default")
            assert result == "value"

    def test_get_or_default_missing(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 404

        with patch.object(client._pool, "request", return_value=mock_resp):
            result = client.get_or_default("key", "default")
            assert result == "default"


class TestClientSet:
    def test_set_success(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200

        with patch.object(client._pool, "request", return_value=mock_resp) as mock_request:
            client.set("test/key", "test value", fmt="json")

            mock_request.assert_called_once()
            args, kwargs = mock_request.call_args
            assert args[0] == "PUT"
            assert "test/key" in args[1]
            assert kwargs["body"] == b"test value"
            assert kwargs["headers"]["X-Stash-Format"] == "json"

    def test_set_empty_key(self):
        client = Client("http://localhost:8080")
        with pytest.raises(ValueError, match="key is required"):
            client.set("", "value")

    def test_set_with_zk_encryption(self):
        client = Client("http://localhost:8080", zk_key="test-passphrase-16")
        mock_resp = MagicMock()
        mock_resp.status = 200

        with patch.object(client._pool, "request", return_value=mock_resp) as mock_request:
            client.set("test/key", "secret value")

            _, kwargs = mock_request.call_args
            body = kwargs["body"]
            assert body.startswith(b"$ZK$")


class TestClientDelete:
    def test_delete_success(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 204

        with patch.object(client._pool, "request", return_value=mock_resp):
            client.delete("test/key")  # should not raise

    def test_delete_not_found(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 404

        with patch.object(client._pool, "request", return_value=mock_resp), pytest.raises(NotFoundError):
            client.delete("missing/key")


class TestClientList:
    def test_list_all(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = json.dumps([
            {
                "key": "key1",
                "size": 10,
                "format": "text",
                "secret": False,
                "zk_encrypted": False,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z",
            },
            {
                "key": "key2",
                "size": 20,
                "format": "json",
                "secret": True,
                "zk_encrypted": True,
                "created_at": "2024-01-15T11:00:00Z",
                "updated_at": "2024-01-15T12:00:00Z",
            },
        ]).encode()

        with patch.object(client._pool, "request", return_value=mock_resp):
            keys = client.list()
            assert len(keys) == 2
            assert keys[0].key == "key1"
            assert keys[0].format == "text"
            assert keys[1].key == "key2"
            assert keys[1].secret is True
            assert keys[1].zk_encrypted is True

    def test_list_with_prefix(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"[]"

        with patch.object(client._pool, "request", return_value=mock_resp) as mock_request:
            client.list("app/")

            args, _ = mock_request.call_args
            assert "prefix=app%2F" in args[1]


class TestClientInfo:
    def test_info_found(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = json.dumps([
            {
                "key": "test/key",
                "size": 10,
                "format": "text",
                "secret": False,
                "zk_encrypted": False,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z",
            },
        ]).encode()

        with patch.object(client._pool, "request", return_value=mock_resp):
            info = client.info("test/key")
            assert info.key == "test/key"
            assert info.size == 10

    def test_info_not_found(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"[]"

        with patch.object(client._pool, "request", return_value=mock_resp), pytest.raises(NotFoundError):
            client.info("missing/key")


class TestClientPing:
    def test_ping_success(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200

        with patch.object(client._pool, "request", return_value=mock_resp):
            client.ping()  # should not raise


class TestClientContextManager:
    def test_context_manager(self):
        with Client("http://localhost:8080", zk_key="a" * 16) as client:
            assert client._zk is not None
        # after exit, passphrase should be cleared
        assert client._zk._passphrase == b"\x00" * 16


class TestClientDictLike:
    def test_getitem(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"value"

        with patch.object(client._pool, "request", return_value=mock_resp):
            assert client["key"] == "value"

    def test_setitem(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200

        with patch.object(client._pool, "request", return_value=mock_resp):
            client["key"] = "value"

    def test_delitem(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 204

        with patch.object(client._pool, "request", return_value=mock_resp):
            del client["key"]

    def test_contains_true(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = json.dumps([{
            "key": "test/key",
            "size": 10,
            "format": "text",
            "secret": False,
            "zk_encrypted": False,
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T10:30:00Z",
        }]).encode()

        with patch.object(client._pool, "request", return_value=mock_resp):
            assert "test/key" in client

    def test_contains_false(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"[]"

        with patch.object(client._pool, "request", return_value=mock_resp):
            assert "missing/key" not in client


class TestClientResponseError:
    def test_unexpected_status_code(self):
        client = Client("http://localhost:8080")
        mock_resp = MagicMock()
        mock_resp.status = 500

        with patch.object(client._pool, "request", return_value=mock_resp), pytest.raises(ResponseError) as exc_info:
            client.get("key")
        assert exc_info.value.status_code == 500
        assert "HTTP 500" in str(exc_info.value)


class TestClientWithToken:
    def test_token_in_headers(self):
        client = Client("http://localhost:8080", token="test-token")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"value"

        with patch.object(client._pool, "request", return_value=mock_resp) as mock_request:
            client.get("key")

            _, kwargs = mock_request.call_args
            assert kwargs["headers"]["Authorization"] == "Bearer test-token"
