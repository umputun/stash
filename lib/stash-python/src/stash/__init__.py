"""Stash Python client library.

A Python client for the Stash KV configuration service with full feature
parity: CRUD operations, authentication, and zero-knowledge encryption
compatible with the Go implementation.

Example:
    >>> from stash import Client
    >>> client = Client("http://localhost:8080")
    >>> client.set("app/config", '{"debug": true}', fmt="json")
    >>> value = client.get("app/config")
    >>> print(value)
    {"debug": true}
"""

from stash.client import Client, Subscription, SubscriptionEvent
from stash.errors import (
    ConnectionError,
    DecryptionError,
    ForbiddenError,
    NotFoundError,
    ResponseError,
    StashError,
    UnauthorizedError,
)
from stash.types import KeyInfo

__version__ = "0.1.0"

__all__ = [
    "Client",
    "ConnectionError",
    "DecryptionError",
    "ForbiddenError",
    "KeyInfo",
    "NotFoundError",
    "ResponseError",
    "StashError",
    "Subscription",
    "SubscriptionEvent",
    "UnauthorizedError",
    "__version__",
]
