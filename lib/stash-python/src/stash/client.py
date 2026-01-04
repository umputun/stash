"""HTTP client for the Stash KV service."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import quote, urljoin

import sseclient
import urllib3

from stash.errors import (
    ConnectionError,
    ForbiddenError,
    NotFoundError,
    ResponseError,
    UnauthorizedError,
)
from stash.types import KeyInfo
from stash.zk import ZKCrypto, is_zk_encrypted

if TYPE_CHECKING:
    from types import TracebackType

# defaults
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3


@dataclass(frozen=True, slots=True)
class SubscriptionEvent:
    """Immutable event from SSE subscription."""

    key: str
    action: str  # create, update, delete
    timestamp: str


class Subscription:
    """SSE subscription with Pythonic iterator protocol and auto-reconnection."""

    def __init__(self, url: str, headers: dict[str, str], connect_timeout: float):
        """Create a new subscription.

        Args:
            url: SSE endpoint URL
            headers: HTTP headers for the request
            connect_timeout: Connection timeout in seconds (no read timeout for streaming)
        """
        self._url = url
        self._headers = headers
        # use connect-only timeout for SSE streaming (no total/read timeout)
        self._pool = urllib3.PoolManager(timeout=urllib3.Timeout(connect=connect_timeout))
        self._closed = threading.Event()

    def __iter__(self) -> Iterator[SubscriptionEvent]:
        """Allows: for event in subscription: ..."""
        return self.events()

    def events(self) -> Iterator[SubscriptionEvent]:
        """Generate events with automatic reconnection.

        Yields:
            SubscriptionEvent for each key change

        Reconnects automatically on connection failure with exponential backoff.
        """
        delay = 1.0  # 1s initial
        while not self._closed.is_set():
            response = None
            try:
                response = self._pool.request("GET", self._url, headers=self._headers, preload_content=False)
                client = sseclient.SSEClient(response)
                delay = 1.0  # reset on successful connection
                for sse_event in client.events():
                    if self._closed.is_set():
                        break
                    if sse_event.event == "change":
                        try:
                            data = json.loads(sse_event.data)
                            yield SubscriptionEvent(key=data["key"], action=data["action"], timestamp=data["timestamp"])
                        except (json.JSONDecodeError, KeyError, TypeError):
                            continue  # skip malformed events
            except Exception:
                if self._closed.is_set():
                    break
                time.sleep(delay)
                delay = min(delay * 2, 30.0)  # max 30s
            finally:
                if response is not None:
                    response.release_conn()

    def close(self) -> None:
        """Terminate the subscription."""
        self._closed.set()

    def __enter__(self) -> Subscription:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


class Client:
    """Stash KV service client."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        zk_key: str | None = None,
    ):
        """Create a new Stash client.

        Args:
            base_url: Stash server URL
            token: Bearer token for authentication
            timeout: Request timeout in seconds
            retries: Number of retry attempts for failed requests
            zk_key: Passphrase for zero-knowledge encryption (min 16 chars)

        Raises:
            ValueError: If base_url is empty or zk_key is too short
        """
        if not base_url:
            raise ValueError("base_url is required")

        # normalize base URL
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

        # configure HTTP pool with retries
        self._pool = urllib3.PoolManager(
            retries=urllib3.Retry(total=retries, backoff_factor=0.1),
            timeout=urllib3.Timeout(total=timeout),
        )

        # initialize ZK encryption if passphrase provided
        self._zk: ZKCrypto | None = None
        if zk_key:
            self._zk = ZKCrypto(zk_key)

    def _headers(self) -> dict[str, str]:
        """Build request headers."""
        headers = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> urllib3.HTTPResponse:
        """Make an HTTP request."""
        url = urljoin(self._base_url + "/", path.lstrip("/"))
        headers = self._headers()
        if extra_headers:
            headers.update(extra_headers)

        try:
            return self._pool.request(method, url, body=body, headers=headers)
        except urllib3.exceptions.HTTPError as e:
            raise ConnectionError(f"connection failed: {e}") from e

    def _check_response(self, resp: urllib3.HTTPResponse) -> None:
        """Check response status and raise appropriate errors."""
        if resp.status in (200, 201, 204):
            return
        if resp.status == 404:
            raise NotFoundError("key not found")
        if resp.status == 401:
            raise UnauthorizedError("unauthorized")
        if resp.status == 403:
            raise ForbiddenError("forbidden")
        raise ResponseError(resp.status)

    def get(self, key: str) -> str:
        """Get value as string.

        Args:
            key: Key to retrieve

        Returns:
            Value as string

        Raises:
            NotFoundError: If key doesn't exist
            DecryptionError: If ZK decryption fails
        """
        return self.get_bytes(key).decode()

    def get_or_default(self, key: str, default: str) -> str:
        """Get value or return default if key doesn't exist.

        Args:
            key: Key to retrieve
            default: Default value to return if key doesn't exist

        Returns:
            Value as string or default
        """
        try:
            return self.get(key)
        except NotFoundError:
            return default

    def get_bytes(self, key: str) -> bytes:
        """Get value as bytes.

        Args:
            key: Key to retrieve

        Returns:
            Value as bytes

        Raises:
            NotFoundError: If key doesn't exist
            DecryptionError: If ZK decryption fails
        """
        if not key:
            raise ValueError("key is required")

        resp = self._request("GET", f"/kv/{quote(key, safe='/')}")
        self._check_response(resp)

        data = resp.data

        # decrypt if ZK-encrypted and we have the key
        if self._zk and is_zk_encrypted(data):
            return self._zk.decrypt(data)

        return data

    def set(self, key: str, value: str, *, fmt: str = "text") -> None:
        """Set value with format.

        Args:
            key: Key to set
            value: Value to store
            fmt: Value format (text, json, yaml, xml, toml, ini, hcl, shell)

        Raises:
            ValueError: If key is empty
        """
        if not key:
            raise ValueError("key is required")

        body = value.encode()

        # encrypt if ZK key is configured
        if self._zk:
            body = self._zk.encrypt(body)

        headers = {"X-Stash-Format": fmt}
        resp = self._request("PUT", f"/kv/{quote(key, safe='/')}", body=body, extra_headers=headers)
        self._check_response(resp)

    def delete(self, key: str) -> None:
        """Delete a key.

        Args:
            key: Key to delete

        Raises:
            NotFoundError: If key doesn't exist
        """
        if not key:
            raise ValueError("key is required")

        resp = self._request("DELETE", f"/kv/{quote(key, safe='/')}")
        self._check_response(resp)

    def list(self, prefix: str = "") -> list[KeyInfo]:
        """List keys with optional prefix filter.

        Args:
            prefix: Prefix to filter keys (empty string for all keys)

        Returns:
            List of KeyInfo objects
        """
        path = "/kv/"
        if prefix:
            path += f"?prefix={quote(prefix, safe='')}"

        resp = self._request("GET", path)
        self._check_response(resp)

        data = json.loads(resp.data.decode())
        return [KeyInfo.from_dict(item) for item in data]

    def info(self, key: str) -> KeyInfo:
        """Get key metadata.

        Args:
            key: Key to get info for

        Returns:
            KeyInfo object

        Raises:
            NotFoundError: If key doesn't exist
        """
        if not key:
            raise ValueError("key is required")

        # use list with exact key as prefix and find exact match
        keys = self.list(key)
        for k in keys:
            if k.key == key:
                return k

        raise NotFoundError("key not found")

    def ping(self) -> None:
        """Check server connectivity.

        Raises:
            ConnectionError: If connection fails
        """
        resp = self._request("GET", "/ping")
        self._check_response(resp)

    def subscribe(self, key: str) -> Subscription:
        """Subscribe to changes for an exact key.

        Args:
            key: The exact key to monitor

        Returns:
            Subscription that yields SubscriptionEvent objects

        Example:
            with client.subscribe("app/config") as sub:
                for event in sub:
                    print(f"{event.action}: {event.key}")
        """
        if not key:
            raise ValueError("key is required")
        url = urljoin(self._base_url + "/", f"kv/subscribe/{quote(key, safe='/')}")
        return Subscription(url, self._headers(), self._timeout)

    def subscribe_prefix(self, prefix: str) -> Subscription:
        """Subscribe to changes for all keys with a prefix.

        Args:
            prefix: The prefix to monitor (e.g., "app" matches "app/config", "app/db")

        Returns:
            Subscription that yields SubscriptionEvent objects

        Example:
            with client.subscribe_prefix("app") as sub:
                for event in sub:
                    print(f"{event.action}: {event.key}")
        """
        if not prefix:
            raise ValueError("prefix is required")
        url = urljoin(self._base_url + "/", f"kv/subscribe/{quote(prefix, safe='/')}/*")
        return Subscription(url, self._headers(), self._timeout)

    def subscribe_all(self) -> Subscription:
        """Subscribe to changes for all keys.

        Returns:
            Subscription that yields SubscriptionEvent objects

        Example:
            with client.subscribe_all() as sub:
                for event in sub:
                    print(f"{event.action}: {event.key}")
        """
        url = urljoin(self._base_url + "/", "kv/subscribe/*")
        return Subscription(url, self._headers(), self._timeout)

    def close(self) -> None:
        """Clear ZK passphrase from memory.

        Call this when the client is no longer needed.
        """
        if self._zk:
            self._zk.clear()

    # context manager support
    def __enter__(self) -> Client:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    # dict-like access
    def __getitem__(self, key: str) -> str:
        return self.get(key)

    def __setitem__(self, key: str, value: str) -> None:
        self.set(key, value)

    def __delitem__(self, key: str) -> None:
        self.delete(key)

    def __contains__(self, key: str) -> bool:
        try:
            self.info(key)
            return True
        except NotFoundError:
            return False
