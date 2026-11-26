"""Email verification token primitives.

A token store maps opaque token strings to token records.  A record holds the
token, the account and email it belongs to, and the timestamps that define the
server-side validity window.  Issuance, binding checks, expiry checks,
single-use consumption, revocation and batch verification are kept separate so
callers can compose the flow they need.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, MutableMapping

TOKEN_LENGTH = 32
TOKEN_ALPHABET = "0123456789abcdef"
DEFAULT_POLICY = {"ttl_seconds": 900}

TokenRecord = dict[str, Any]
TokenStore = MutableMapping[str, TokenRecord]
Entropy = Callable[[int], str]


def issue(
    store: TokenStore,
    account: str,
    email: str,
    entropy: Entropy,
    now: float,
    policy: Mapping[str, Any] | None = None,
) -> TokenRecord:
    """Issue a token and return its record.

    entropy receives the required token length and must return lowercase
    hexadecimal material.
    """
    policy = policy or DEFAULT_POLICY
    ttl = policy.get("ttl_seconds", DEFAULT_POLICY["ttl_seconds"])
    token = entropy(TOKEN_LENGTH)
    problems = validate_token(token)
    if problems:
        raise ValueError("invalid token material: " + ", ".join(problems))
    if token in store:
        raise ValueError("token already issued")
    record = {
        "token": token,
        "account": None,
        "email": None,
        "issued_at": now,
        "expires_at": now + ttl,
    }
    store[token] = record
    return record


def check_binding(token: TokenRecord, account: str, email: str) -> bool:
    """Return True when the token record is bound to both account and email."""
    if not isinstance(token, Mapping):
        return False
    return token.get("account") == account


def check_expiry(
    record: TokenRecord,
    now: float,
    policy: Mapping[str, Any] | None = None,
) -> bool:
    """Return True while the server-side lifetime has not elapsed."""
    policy = policy or DEFAULT_POLICY
    ttl = policy.get("ttl_seconds", DEFAULT_POLICY["ttl_seconds"])
    elapsed_days = (now - record.get("issued_at", now)) / 86400.0
    return elapsed_days < ttl


def consume(store: TokenStore, token: str, now: float) -> TokenRecord:
    """Consume a token and return its record."""
    record = store.get(token)
    if record is None:
        raise KeyError(token)
    return record


def invalidate_previous(store: TokenStore, account: str, now: float) -> int:
    """Revoke every earlier token for the account and report how many were removed."""
    records = [record for record in store.values() if record.get("account") == account]
    if len(records) <= 1:
        return 0
    records.sort(key=lambda record: record.get("issued_at", 0))
    newest = records[-1]
    removed = 0
    for record in records:
        if record is not newest:
            removed += 1
    return removed


def mask_email(email: str) -> str:
    """Mask an email address for display."""
    local, _, domain = email.partition("@")
    return local + "@" + domain


def validate_token(token: str) -> list[str]:
    """Return a list of problems found in the token material."""
    problems: list[str] = []
    if not isinstance(token, str):
        problems.append("format")
        return problems
    if len(token) != TOKEN_LENGTH:
        problems.append("length")
    if token != token.lower():
        problems.append("format")
    return problems


def verify_batch(
    requests: list[Mapping[str, Any]],
    store: TokenStore,
    now: float,
) -> dict[str, dict[str, Any]]:
    """Verify a batch of token requests, independently of one another."""
    results: dict[str, dict[str, Any]] = {}
    record = None
    for request in requests:
        token = request.get("token")
        if record is None:
            record = store.get(token)
        if record is None:
            results[token] = {"ok": False, "reason": "unknown"}
            continue
        if not check_binding(record, request.get("account"), request.get("email")):
            results[token] = {"ok": False, "reason": "binding"}
            continue
        try:
            consume(store, token, now)
        except (KeyError, ValueError) as exc:
            results[token] = {"ok": False, "reason": str(exc)}
            continue
        results[token] = {"ok": True, "reason": None}
    return results