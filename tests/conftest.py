"""Shared pytest fixtures and lightweight async HTTP fakes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from yarl import URL

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from types import TracebackType


async def _default_request_impl(*_args: object, **_kwargs: object) -> FakeResponse:
    return FakeResponse()


def _default_get_impl(*_args: object, **_kwargs: object) -> FakeResponse:
    return FakeResponse()


class FakeCookieJar:
    """Minimal cookie jar stub used by test sessions."""

    def __init__(self) -> None:
        """Initialize tracked cookie updates and clear state."""
        self.updated: list[object] = []
        self.cleared = False

    def update_cookies(self, cookies: object) -> None:
        """Record cookie updates performed by API code under test."""
        self.updated.append(cookies)

    def clear(self) -> None:
        """Mark cookie jar as cleared."""
        self.cleared = True


@dataclass
class FakeResponse:
    """Simple async response stub compatible with aiohttp usage in tests."""

    status: int = 200
    text_data: str = ""
    json_data: object | None = None
    content_type: str = "application/json"
    cookies: dict[str, object] | None = None

    async def text(self) -> str:
        """Return configured plain-text payload."""
        return self.text_data

    async def json(
        self,
        _content_type: str | None = None,
        **_kwargs: object,
    ) -> object:
        """Return configured JSON payload, ignoring content type."""
        return self.json_data


class _AsyncResponseContext:
    """Async context manager wrapper for fake GET responses."""

    def __init__(self, response: FakeResponse) -> None:
        """Store the fake response to return from async context entry."""
        self._response = response

    async def __aenter__(self) -> FakeResponse:
        """Return the wrapped fake response on context entry."""
        return self._response

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        """Do not suppress exceptions raised in context-managed blocks."""
        return False


class FakeSession:
    """Minimal session stub exposing request/get and cookie jar behavior."""

    def __init__(
        self,
        request_impl: Callable[..., Awaitable[FakeResponse]] | None = None,
        get_impl: Callable[..., FakeResponse] | None = None,
    ) -> None:
        """Initialize optional request handlers and call tracking containers."""
        self._request_impl = request_impl or _default_request_impl
        self._get_impl = get_impl or _default_get_impl
        self.cookie_jar = FakeCookieJar()
        self.requests: list[dict[str, object]] = []
        self.get_calls: list[dict[str, object]] = []

    async def request(self, *_args: object, **_kwargs: object) -> FakeResponse:
        """Record and dispatch a fake request invocation."""
        self.requests.append({"args": _args, "kwargs": _kwargs})
        return await self._request_impl(*_args, **_kwargs)

    def get(self, *_args: object, **_kwargs: object) -> _AsyncResponseContext:
        """Record and dispatch a fake GET call returning async context."""
        self.get_calls.append({"args": _args, "kwargs": _kwargs})
        result = self._get_impl(*_args, **_kwargs)
        return _AsyncResponseContext(result)


@pytest.fixture
def base_url() -> URL:
    """Provide a deterministic router URL for tests."""
    return URL("http://router.local")
