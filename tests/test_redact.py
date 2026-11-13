from __future__ import annotations

from collections.abc import Callable

import pytest

from codesift.redact import ELLIPSIS, Redactor, mask


def test_mask_shows_prefix_and_length() -> None:
    value = "abcdefghijklmnopqrstuvwxyz"
    assert mask(value) == f"abcd{ELLIPSIS}(len 26)"


def test_mask_short_value_reveals_nothing() -> None:
    assert mask("short1") == f"{ELLIPSIS}(len 6)"


def test_known_secret_is_masked(fake_secret: Callable[[str], str]) -> None:
    secret = fake_secret("generic")
    r = Redactor([secret])
    out = r.scrub(f"value is {secret} and again {secret}")
    assert secret not in out
    assert out.count(ELLIPSIS) == 2


def test_too_short_known_secret_ignored() -> None:
    r = Redactor(["abc"])
    assert len(r) == 0


@pytest.mark.parametrize("kind", ["github", "aws", "openai"])
def test_well_known_token_shapes_masked(fake_secret: Callable[[str], str], kind: str) -> None:
    secret = fake_secret(kind)
    out = Redactor().scrub(f"found {secret} in file")
    assert secret not in out
    assert ELLIPSIS in out


def test_bearer_header_masked(fake_secret: Callable[[str], str]) -> None:
    secret = fake_secret("generic")
    out = Redactor().scrub(f"Authorization: Bearer {secret}")
    assert secret not in out
    assert out.startswith("Authorization: Bearer ")


def test_url_credentials_masked(fake_secret: Callable[[str], str]) -> None:
    secret = fake_secret("generic")
    out = Redactor().scrub(f"clone https://user:{secret}@example.com/repo.git")
    assert secret not in out
    assert "@example.com/repo.git" in out


def test_key_value_masked(fake_secret: Callable[[str], str]) -> None:
    secret = fake_secret("generic")
    for line in (f"API_KEY={secret}", f'db_password: "{secret}"', f"client_secret = '{secret}'"):
        assert secret not in Redactor().scrub(line)


def test_private_key_block_masked(fake_secret: Callable[[str], str]) -> None:
    body = fake_secret("generic")
    header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    footer = "-----END " + "OPENSSH PRIVATE KEY-----"
    out = Redactor().scrub(f"x\n{header}\n{body}\n{footer}\ny")
    assert body not in out
    assert "(redacted)" in out
    assert out.startswith("x\n") and out.endswith("\ny")


def test_scrub_is_idempotent(fake_secret: Callable[[str], str]) -> None:
    secret = fake_secret("github")
    r = Redactor([secret])
    once = r.scrub(f"token={secret}")
    assert r.scrub(once) == once


def test_plain_text_untouched() -> None:
    text = "def add(a, b):\n    return a + b  # simple"
    assert Redactor().scrub(text) == text
