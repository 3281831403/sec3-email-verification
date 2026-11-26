"""Public acceptance tests for the email verification token API."""

from __future__ import annotations

import pytest

from emailv.token import (
    check_binding,
    check_expiry,
    consume,
    issue,
    verify_batch,
)

POLICY = {"ttl_seconds": 900}


def _entropy(*characters: str):
    sequence = iter(characters)

    def draw(length: int) -> str:
        return next(sequence) * length

    return draw


def test_issue_token_binds_account_and_email() -> None:
    store = {}
    record = issue(store, "alice", "alice@example.com", _entropy("a"), 1000, POLICY)
    assert record["token"] == "a" * 32
    assert record["account"] == "alice"
    assert record["email"] == "alice@example.com"
    assert store["a" * 32] is record


def test_check_binding_requires_account_and_email() -> None:
    store = {}
    record = issue(store, "alice", "alice@example.com", _entropy("b"), 1000, POLICY)
    assert check_binding(record, "alice", "alice@example.com") is True
    assert check_binding(record, "alice", "mallory@example.com") is False


def test_consume_is_single_use() -> None:
    store = {}
    record = issue(store, "alice", "alice@example.com", _entropy("c"), 1000, POLICY)
    consumed = consume(store, record["token"], 1001)
    assert consumed["token"] == record["token"]
    assert record["token"] not in store
    with pytest.raises(KeyError):
        consume(store, record["token"], 1001)


def test_expired_token_is_rejected() -> None:
    store = {}
    record = issue(store, "alice", "alice@example.com", _entropy("d"), 1000, POLICY)
    assert check_expiry(record, 1901, POLICY) is False
    with pytest.raises(ValueError):
        consume(store, record["token"], 1901)


def test_batch_verification_keeps_tokens_independent() -> None:
    store = {}
    entropy = _entropy("e", "f")
    first = issue(store, "alice", "alice@example.com", entropy, 1000, POLICY)
    second = issue(store, "bob", "bob@example.com", entropy, 1000, POLICY)
    requests = [
        {"token": first["token"], "account": "alice", "email": "alice@example.com"},
        {"token": second["token"], "account": "bob", "email": "bob@example.com"},
    ]
    results = verify_batch(requests, store, 1001)
    assert results[first["token"]]["ok"] is True
    assert results[second["token"]]["ok"] is True