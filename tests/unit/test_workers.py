import asyncio
import unittest

from velora.workers import bounded_gather


class TestWorkers(unittest.IsolatedAsyncioTestCase):
    async def test_bounded_gather_preserves_order(self):
        async def f(x):
            await asyncio.sleep(0.001)
            return x * 2
        out = await bounded_gather([f(i) for i in range(10)], limit=3)
        self.assertEqual(out, [i * 2 for i in range(10)])

    async def test_respects_concurrency_limit(self):
        running = 0
        peak = 0
        async def f():
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0.01)
            running -= 1
            return 1
        await bounded_gather([f() for _ in range(12)], limit=4)
        self.assertLessEqual(peak, 4)


if __name__ == "__main__":
    unittest.main()
