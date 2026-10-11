"""In-memory rate limiter middleware for FastAPI.

Token-bucket algorithm — prevents abuse of NVD-querying scan
endpoints without requiring Redis or external dependencies.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


@dataclass
class TokenBucket:
    """Token bucket for a single client."""

    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)

    def __post_init__(self):
        self.tokens = float(self.capacity)

    def consume(self) -> bool:
        """Try to consume a token. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until next token is available."""
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.refill_rate


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """Per-client rate limiter using token bucket algorithm.

    Args:
        app: The ASGI application.
        requests_per_minute: Max sustained requests per minute per client.
        burst: Max burst size (bucket capacity).
        exempt_paths: Paths that bypass rate limiting (e.g., /health).
    """

    def __init__(
        self,
        app,
        requests_per_minute: int = 30,
        burst: int = 10,
        exempt_paths: set[str] | None = None,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst = burst
        self.refill_rate = requests_per_minute / 60.0
        self.exempt_paths = exempt_paths or {"/health", "/docs", "/openapi.json"}
        self._buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(capacity=burst, refill_rate=self.refill_rate)
        )

    def _get_client_key(self, request: Request) -> str:
        """Extract client identifier from request."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        client_key = self._get_client_key(request)
        bucket = self._buckets[client_key]

        if not bucket.consume():
            retry_after = round(bucket.retry_after, 1)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(int(retry_after + 1))},
            )

        response = await call_next(request)
        return response
