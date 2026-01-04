"""Tests for SSE subscription functionality."""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest
import urllib3

from stash.client import Client, Subscription, SubscriptionEvent


class TestSubscriptionEvent:
    """Tests for SubscriptionEvent dataclass."""

    def test_create_event(self):
        event = SubscriptionEvent(key="app/config", action="update", timestamp="2025-01-03T10:30:00Z")
        assert event.key == "app/config"
        assert event.action == "update"
        assert event.timestamp == "2025-01-03T10:30:00Z"

    def test_event_is_immutable(self):
        event = SubscriptionEvent(key="app/config", action="update", timestamp="2025-01-03T10:30:00Z")
        with pytest.raises(AttributeError):
            event.key = "other"  # type: ignore

    def test_event_equality(self):
        event1 = SubscriptionEvent(key="app/config", action="update", timestamp="2025-01-03T10:30:00Z")
        event2 = SubscriptionEvent(key="app/config", action="update", timestamp="2025-01-03T10:30:00Z")
        assert event1 == event2


class TestSubscription:
    """Tests for Subscription class."""

    def test_subscription_is_iterable(self):
        sub = Subscription("http://test/subscribe/key", {}, 30.0)
        assert hasattr(sub, "__iter__")

    def test_subscription_close(self):
        sub = Subscription("http://test/subscribe/key", {}, 30.0)
        assert not sub._closed.is_set()
        sub.close()
        assert sub._closed.is_set()

    def test_subscription_context_manager(self):
        with Subscription("http://test/subscribe/key", {}, 30.0) as sub:
            assert not sub._closed.is_set()
        assert sub._closed.is_set()

    def test_subscription_uses_connect_only_timeout(self):
        """Test that subscription uses connect-only timeout (no read timeout)."""
        sub = Subscription("http://test/subscribe/key", {}, 30.0)
        # verify pool has connect-only timeout
        timeout = sub._pool.connection_pool_kw.get("timeout")
        assert timeout is not None
        assert timeout.connect_timeout == 30.0
        assert timeout.read_timeout is None  # no read timeout for streaming

    def test_subscription_events_parsing(self):
        """Test that events are parsed correctly from SSE stream."""
        # create a mock SSE client that returns events
        mock_sse_event = MagicMock()
        mock_sse_event.event = "change"
        mock_sse_event.data = json.dumps({"key": "app/config", "action": "update", "timestamp": "2025-01-03T10:30:00Z"})

        mock_response = MagicMock()

        with patch("stash.client.sseclient.SSEClient") as mock_sse_client, patch.object(
            urllib3.PoolManager, "request", return_value=mock_response
        ):
            mock_sse_client.return_value.events.return_value = iter([mock_sse_event])

            sub = Subscription("http://test/subscribe/key", {}, 30.0)

            # get one event and close
            events = []
            for event in sub:
                events.append(event)
                sub.close()
                break

            assert len(events) == 1
            assert events[0].key == "app/config"
            assert events[0].action == "update"

    def test_subscription_ignores_non_change_events(self):
        """Test that non-change events are ignored."""
        # create mock SSE events with different types
        mock_ping_event = MagicMock()
        mock_ping_event.event = "ping"
        mock_ping_event.data = ""

        mock_change_event = MagicMock()
        mock_change_event.event = "change"
        mock_change_event.data = json.dumps({"key": "app/config", "action": "create", "timestamp": "2025-01-03T10:30:00Z"})

        mock_response = MagicMock()

        with patch("stash.client.sseclient.SSEClient") as mock_sse_client, patch.object(
            urllib3.PoolManager, "request", return_value=mock_response
        ):
            mock_sse_client.return_value.events.return_value = iter([mock_ping_event, mock_change_event])

            sub = Subscription("http://test/subscribe/key", {}, 30.0)

            events = []
            for event in sub:
                events.append(event)
                sub.close()
                break

            # should only get the change event, ping should be ignored
            assert len(events) == 1
            assert events[0].action == "create"

    def test_subscription_reconnects_on_error(self):
        """Test that subscription reconnects on connection error."""
        call_count = [0]

        def mock_request(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("connection failed")
            # second call succeeds
            return MagicMock()

        mock_sse_event = MagicMock()
        mock_sse_event.event = "change"
        mock_sse_event.data = json.dumps({"key": "test", "action": "update", "timestamp": "2025-01-03T10:30:00Z"})

        with patch("stash.client.sseclient.SSEClient") as mock_sse_client, patch.object(
            urllib3.PoolManager, "request", side_effect=mock_request
        ):
            mock_sse_client.return_value.events.return_value = iter([mock_sse_event])

            sub = Subscription("http://test/subscribe/key", {}, 30.0)

            # start consuming in a thread
            events = []

            def consume():
                for event in sub:
                    events.append(event)
                    sub.close()
                    break

            thread = threading.Thread(target=consume)
            thread.start()
            thread.join(timeout=3)

            # verify reconnection happened
            assert call_count[0] >= 2
            assert len(events) == 1


class TestClientSubscribeMethods:
    """Tests for Client subscribe methods."""

    def test_subscribe_creates_subscription(self):
        client = Client("http://localhost:8080")
        sub = client.subscribe("app/config")
        assert isinstance(sub, Subscription)
        assert "kv/subscribe/app/config" in sub._url
        sub.close()

    def test_subscribe_empty_key_raises(self):
        client = Client("http://localhost:8080")
        with pytest.raises(ValueError, match="key is required"):
            client.subscribe("")

    def test_subscribe_includes_auth_header(self):
        client = Client("http://localhost:8080", token="secret-token")
        sub = client.subscribe("app/config")
        assert sub._headers.get("Authorization") == "Bearer secret-token"
        sub.close()

    def test_subscribe_prefix_creates_subscription(self):
        client = Client("http://localhost:8080")
        sub = client.subscribe_prefix("app")
        assert isinstance(sub, Subscription)
        assert "kv/subscribe/app/*" in sub._url
        sub.close()

    def test_subscribe_prefix_empty_raises(self):
        client = Client("http://localhost:8080")
        with pytest.raises(ValueError, match="prefix is required"):
            client.subscribe_prefix("")

    def test_subscribe_all_creates_subscription(self):
        client = Client("http://localhost:8080")
        sub = client.subscribe_all()
        assert isinstance(sub, Subscription)
        assert "kv/subscribe/*" in sub._url
        sub.close()

    def test_subscribe_url_encoding(self):
        client = Client("http://localhost:8080")
        sub = client.subscribe("app/config/database")
        assert "kv/subscribe/app/config/database" in sub._url
        sub.close()
