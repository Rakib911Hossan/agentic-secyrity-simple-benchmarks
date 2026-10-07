"""A minimal per-IP sliding-window rate limiter, in-memory.

Good enough for a single-process dev/demo deployment (which this lab project
is). A production deployment with multiple workers would need a shared store
(e.g. Redis) instead — noted here rather than hidden.
"""
import time
from collections import defaultdict, deque
from functools import wraps

from flask import request, abort, current_app

_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(max_requests: int = 10, window_seconds: int = 60):
    """Limits a view to `max_requests` calls per `window_seconds` per client IP.
    Skipped entirely in vulnerable mode, to keep that mode's gaps isolated
    to one cause at a time for the validation suite's checks."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if current_app.config.get("MODE", "secure") != "secure":
                return view(*args, **kwargs)
            if request.method != "POST":
                # Only state-changing attempts count against the budget;
                # loading the form itself is free.
                return view(*args, **kwargs)

            ip = request.remote_addr or "unknown"
            key = f"{view.__name__}:{ip}"
            now = time.time()
            bucket = _hits[key]

            while bucket and now - bucket[0] > window_seconds:
                bucket.popleft()

            if len(bucket) >= max_requests:
                abort(429, description="Too many requests. Please slow down and try again shortly.")

            bucket.append(now)
            return view(*args, **kwargs)
        return wrapped
    return decorator
