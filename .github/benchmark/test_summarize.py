import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("summarize.py")
SPEC = importlib.util.spec_from_file_location("inbound_benchmark_summarize", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SUMMARIZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARIZE)


def report(*, errors=0, rate=100.0, seconds=5.0):
    return {
        "duration": "5s",
        "results": [
            {
                "scenario": "tcp-short",
                "seconds": seconds,
                "operations": 500,
                "rate": rate,
                "unit": "op/s",
                "errors": errors,
            }
        ],
    }


class LoadResultsTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_report(self, variant, repetition, value):
        path = self.root / "raw" / variant / f"{repetition}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_rejects_whole_report_when_one_measurement_is_invalid(self):
        value = report()
        value["results"].append(
            {
                "scenario": "udp-pps",
                "seconds": 5.0,
                "operations": 10,
                "rate": 2.0,
                "unit": "op/s",
                "errors": 1,
            }
        )
        self.write_report("ebpf-local", "1", value)

        results, rejected = SUMMARIZE.load_results(self.root)

        self.assertEqual({}, results)
        self.assertEqual(1, len(rejected))
        self.assertIn("reported 1 errors", rejected[0][1])

    def test_rejects_measurement_that_exceeds_duration_tolerance(self):
        self.write_report("direct", "1", report(seconds=7.0))

        results, rejected = SUMMARIZE.load_results(self.root)

        self.assertEqual({}, results)
        self.assertEqual(1, len(rejected))
        self.assertIn("requested 5s", rejected[0][1])

    def test_validation_failure_rejects_all_variant_reports(self):
        self.write_report("ebpf-local", "1", report())
        self.write_report("direct", "1", report())
        (self.root / "failures.tsv").write_text(
            "ebpf-local-leak-check\tvalidation\t1\n", encoding="utf-8"
        )

        results, rejected = SUMMARIZE.load_results(self.root)

        self.assertNotIn(("ebpf-local", "tcp-short"), results)
        self.assertIn(("direct", "tcp-short"), results)
        self.assertEqual("variant interception validation failed", rejected[0][1])


if __name__ == "__main__":
    unittest.main()
