"""Tests for data types."""

from stash.types import KeyInfo, _parse_datetime


class TestParseDatetime:
    def test_rfc3339_with_z(self):
        dt = _parse_datetime("2024-01-15T10:30:00Z")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 10
        assert dt.minute == 30
        assert dt.second == 0
        assert dt.tzinfo is not None

    def test_rfc3339_with_offset(self):
        dt = _parse_datetime("2024-01-15T10:30:00+05:00")
        assert dt.year == 2024
        assert dt.hour == 10

    def test_rfc3339_with_nanoseconds(self):
        dt = _parse_datetime("2024-01-15T10:30:00.123456789Z")
        assert dt.year == 2024
        # python truncates to microseconds
        assert dt.microsecond == 123456


class TestKeyInfo:
    def test_from_dict_minimal(self):
        data = {
            "key": "test/key",
            "size": 100,
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T11:00:00Z",
        }
        info = KeyInfo.from_dict(data)
        assert info.key == "test/key"
        assert info.size == 100
        assert info.format == "text"  # default
        assert info.secret is False  # default
        assert info.zk_encrypted is False  # default

    def test_from_dict_full(self):
        data = {
            "key": "secrets/api-key",
            "size": 256,
            "format": "json",
            "secret": True,
            "zk_encrypted": True,
            "created_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T12:00:00Z",
        }
        info = KeyInfo.from_dict(data)
        assert info.key == "secrets/api-key"
        assert info.size == 256
        assert info.format == "json"
        assert info.secret is True
        assert info.zk_encrypted is True
        assert info.created_at.hour == 10
        assert info.updated_at.hour == 12
