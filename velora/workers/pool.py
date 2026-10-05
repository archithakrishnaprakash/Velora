"""A minimal bounded-concurrency task helper."""
from __future__ import annotations

import asyncio
from typing import Awaitable, Iterable, TypeVar

T = TypeVar("T")


async def bounded_gather(aws: Iterable[Awaitable[T]], *, limit: int = 5) -> list[T]:
    """Run awaitables with at most ``limit`` running concurrently, preserving order."""
    sem = asyncio.Semaphore(max(1, limit))
    aws_list = list(aws)

    async def _run(aw: Awaitable[T]) -> T:
        async with sem:
            return await aw

    return await asyncio.gather(*[_run(a) for a in aws_list])
