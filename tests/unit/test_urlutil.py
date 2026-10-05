import unittest

from velora.utils import urlutil as u


class TestUrlUtil(unittest.TestCase):
    def test_normalize_lowercases_and_drops_default_port(self):
        self.assertEqual(u.normalize_url("HTTP://Example.COM:80/a"), "http://example.com/a")
        self.assertEqual(u.normalize_url("https://Example.com:443/"), "https://example.com/")

    def test_normalize_sorts_query_and_drops_tracking(self):
        self.assertEqual(
            u.normalize_url("http://x.com/?b=2&a=1&utm_source=z"),
            "http://x.com/?a=1&b=2",
        )

    def test_normalize_collapses_slashes_and_fragment(self):
        self.assertEqual(u.normalize_url("http://x.com/a//b#frag"), "http://x.com/a/b")

    def test_param_signature_ignores_values(self):
        self.assertEqual(u.param_signature("http://x.com/i?id=1"),
                         u.param_signature("http://x.com/i?id=999"))

    def test_same_origin(self):
        self.assertTrue(u.same_origin("http://x.com/a", "http://x.com:80/b"))
        self.assertFalse(u.same_origin("http://x.com/a", "https://x.com/b"))
        self.assertFalse(u.same_origin("http://x.com/a", "http://y.com/b"))


if __name__ == "__main__":
    unittest.main()
