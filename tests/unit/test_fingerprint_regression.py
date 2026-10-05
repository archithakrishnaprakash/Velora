import unittest

from velora.findings import fingerprint as fp
from velora.models.domain import Finding
from velora.models.enums import Severity


def finding(title="Missing CSP", endpoint="http://lab.local/a", scanner="headers.x",
            category="configuration", severity=Severity.MEDIUM, method="GET"):
    return Finding(scan_id="S", title=title, endpoint=endpoint, scanner=scanner,
                   category=category, severity=severity, method=method)


class TestFingerprint(unittest.TestCase):
    def test_same_issue_has_same_fingerprint_across_scans(self):
        a, b = finding(), finding()
        b.scan_id = "OTHER"
        self.assertEqual(fp.compute(a), fp.compute(b))

    def test_object_ids_in_path_are_collapsed(self):
        a = finding(endpoint="http://lab.local/api/orders/1")
        b = finding(endpoint="http://lab.local/api/orders/9987")
        self.assertEqual(fp.compute(a), fp.compute(b))

    def test_uuid_segments_are_collapsed(self):
        a = finding(endpoint="http://lab.local/u/3f2504e0-4f89-11d3-9a0c-0305e82c3301")
        b = finding(endpoint="http://lab.local/u/9a1204e0-1189-41d3-9a0c-0305e82c9999")
        self.assertEqual(fp.compute(a), fp.compute(b))

    def test_different_endpoints_differ(self):
        self.assertNotEqual(fp.compute(finding(endpoint="http://lab.local/a")),
                            fp.compute(finding(endpoint="http://lab.local/b")))

    def test_different_check_differs(self):
        self.assertNotEqual(fp.compute(finding(scanner="a.b")),
                            fp.compute(finding(scanner="c.d")))

    def test_severity_change_keeps_the_same_fingerprint(self):
        """A severity re-rating must read as persisting, not fixed-plus-new."""
        self.assertEqual(fp.compute(finding(severity=Severity.LOW)),
                         fp.compute(finding(severity=Severity.CRITICAL)))

    def test_port_change_keeps_the_same_fingerprint(self):
        a = finding(endpoint="http://lab.local:8080/a")
        b = finding(endpoint="http://lab.local:9090/a")
        self.assertEqual(fp.compute(a), fp.compute(b))

    def test_numbers_in_title_are_normalized(self):
        a = finding(title="Risky HTTP methods enabled: 3 found")
        b = finding(title="Risky HTTP methods enabled: 5 found")
        self.assertEqual(fp.compute(a), fp.compute(b))

    def test_ensure_is_idempotent(self):
        f = finding()
        first = fp.ensure(f)
        self.assertEqual(first, fp.ensure(f))
        self.assertEqual(f.fingerprint, first)

    def test_index_keeps_highest_severity_duplicate(self):
        low = finding(severity=Severity.LOW)
        high = finding(severity=Severity.HIGH)
        index = fp.index_by_fingerprint([low, high])
        self.assertEqual(len(index), 1)
        self.assertEqual(next(iter(index.values())).severity, Severity.HIGH)

    def test_normalize_endpoint_handles_empty(self):
        self.assertEqual(fp.normalize_endpoint(""), "")


if __name__ == "__main__":
    unittest.main()
