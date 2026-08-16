import pytest

from security_toolkit.core import target_validator as tv


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "ip"),
    ("10.0.0.0/24", "cidr"),
    ("example.com", "domain"),
    ("https://example.com/path?id=1", "url"),
])
def test_classify(value, expected):
    assert tv.classify(value).target_type == expected


def test_classify_invalid():
    assert tv.classify("").valid is False


def test_in_scope_domain_suffix():
    assert tv.in_scope("api.example.com", ["example.com"]) is True
    assert tv.in_scope("evil.com", ["example.com"]) is False


def test_in_scope_cidr():
    assert tv.in_scope("10.0.0.5", ["10.0.0.0/24"]) is True
    assert tv.in_scope("10.0.1.5", ["10.0.0.0/24"]) is False


def test_empty_scope_denies():
    assert tv.in_scope("example.com", []) is False
