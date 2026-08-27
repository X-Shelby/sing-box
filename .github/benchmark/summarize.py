#!/usr/bin/env python3

import json
import math
import re
import statistics
import sys
from pathlib import Path


DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ns|us|ms|s|m|h)")
SCENARIO_UNITS = {
    "tcp-short": "op/s",
    "tcp-upload": "bit/s",
    "tcp-download": "bit/s",
    "udp-pps": "op/s",
    "udp-unconnected-pps": "op/s",
    "udp-churn": "op/s",
}


def format_rate(rate: float, unit: str) -> str:
    if unit == "bit/s":
        for divisor, suffix in ((1e9, "Gbit/s"), (1e6, "Mbit/s"), (1e3, "kbit/s")):
            if rate >= divisor:
                return f"{rate / divisor:.3f} {suffix}"
    if rate >= 1e6:
        return f"{rate / 1e6:.3f} M {unit}"
    if rate >= 1e3:
        return f"{rate / 1e3:.3f} k {unit}"
    return f"{rate:.3f} {unit}"


def parse_duration(value: str) -> float:
    if not isinstance(value, str):
        raise TypeError("duration is not a string")
    normalized = value.replace("\N{MICRO SIGN}", "us").replace("\N{GREEK SMALL LETTER MU}", "us")
    scales = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}
    seconds = 0.0
    position = 0
    for match in DURATION_PART.finditer(normalized):
        if match.start() != position:
            raise ValueError(f"invalid duration {value!r}")
        seconds += float(match.group(1)) * scales[match.group(2)]
        position = match.end()
    if position != len(normalized) or seconds <= 0:
        raise ValueError(f"invalid duration {value!r}")
    return seconds


def validate_report(report: object) -> str | None:
    if not isinstance(report, dict):
        return "top-level value is not an object"
    try:
        expected_seconds = parse_duration(report["duration"])
    except (KeyError, TypeError, ValueError) as error:
        return str(error)
    measurements = report.get("results")
    if not isinstance(measurements, list) or not measurements:
        return "results is empty or missing"
    seen = set()
    lower_seconds = expected_seconds * 0.8
    upper_seconds = expected_seconds + max(1.0, expected_seconds * 0.25)
    for measurement in measurements:
        if not isinstance(measurement, dict):
            return "measurement is not an object"
        scenario = measurement.get("scenario")
        if scenario not in SCENARIO_UNITS:
            return f"unknown scenario {scenario!r}"
        if scenario in seen:
            return f"duplicate scenario {scenario}"
        seen.add(scenario)
        if measurement.get("unit") != SCENARIO_UNITS[scenario]:
            return f"unexpected unit for {scenario}"
        errors = measurement.get("errors")
        if not isinstance(errors, int) or isinstance(errors, bool) or errors != 0:
            return f"{scenario} reported {errors!r} errors"
        rate = measurement.get("rate")
        if not isinstance(rate, (int, float)) or isinstance(rate, bool) or not math.isfinite(rate) or rate <= 0:
            return f"{scenario} has invalid rate {rate!r}"
        seconds = measurement.get("seconds")
        if (
            not isinstance(seconds, (int, float))
            or isinstance(seconds, bool)
            or not math.isfinite(seconds)
            or not lower_seconds <= seconds <= upper_seconds
        ):
            return f"{scenario} measured {seconds!r}s for requested {expected_seconds:g}s"
    return None


def load_failures(root: Path):
    failed_variants = set()
    failed_runs = set()
    failures = root / "failures.tsv"
    if not failures.exists():
        return failed_variants, failed_runs
    for line in failures.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        name, repetition = fields[:2]
        for suffix in ("-interception-check", "-leak-check"):
            if name.endswith(suffix):
                failed_variants.add(name[: -len(suffix)])
                break
        else:
            if repetition != "validation":
                failed_runs.add((name, repetition))
    return failed_variants, failed_runs


def load_results(root: Path):
    results = {}
    rejected = []
    raw_root = root / "raw"
    if not raw_root.exists():
        return results, rejected
    failed_variants, failed_runs = load_failures(root)
    for path in sorted(raw_root.glob("*/*.json")):
        variant = path.parent.name
        relative_path = path.relative_to(root)
        if variant in failed_variants:
            rejected.append((relative_path, "variant interception validation failed"))
            continue
        if (variant, path.stem) in failed_runs:
            rejected.append((relative_path, "benchmark run failed"))
            continue
        try:
            with path.open(encoding="utf-8") as input_file:
                report = json.load(input_file)
        except (OSError, json.JSONDecodeError) as error:
            rejected.append((relative_path, f"invalid JSON: {error}"))
            continue
        reason = validate_report(report)
        if reason is not None:
            rejected.append((relative_path, reason))
            continue
        for measurement in report.get("results", []):
            key = (variant, measurement["scenario"])
            results.setdefault(key, []).append(measurement)
    return results, rejected


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize.py RESULT_DIRECTORY", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    results, rejected = load_results(root)

    print("# Transparent inbound benchmark")
    print()
    run_info = root / "environment" / "run.txt"
    if run_info.exists():
        print("```text")
        print(run_info.read_text(encoding="utf-8").strip())
        print("```")
        print()

    if not results:
        print("No valid benchmark reports were produced.")
    else:
        direct = {
            scenario: statistics.median(item["rate"] for item in measurements)
            for (variant, scenario), measurements in results.items()
            if variant == "direct"
        }
        print("| Variant | Scenario | Median | Relative to direct | Runs | Errors |")
        print("|---|---|---:|---:|---:|---:|")
        variant_order = {
            name: index
            for index, name in enumerate(
                (
                    "direct",
                    "ebpf-local",
                    "ebpf-shared",
                    "redirect",
                    "tproxy",
                    "tun-mixed",
                    "tun-mixed-auto-redirect",
                )
            )
        }
        scenario_order = {
            name: index
            for index, name in enumerate(
                ("tcp-short", "tcp-upload", "tcp-download", "udp-pps", "udp-unconnected-pps", "udp-churn")
            )
        }
        for (variant, scenario), measurements in sorted(
            results.items(),
            key=lambda item: (variant_order.get(item[0][0], 99), scenario_order.get(item[0][1], 99)),
        ):
            median_rate = statistics.median(item["rate"] for item in measurements)
            baseline = direct.get(scenario)
            relative = "baseline" if variant == "direct" else "N/A"
            if variant != "direct" and baseline:
                relative = f"{median_rate / baseline * 100:.1f}%"
            errors = sum(item.get("errors", 0) for item in measurements)
            print(
                f"| {variant} | {scenario} | {format_rate(median_rate, measurements[0]['unit'])} "
                f"| {relative} | {len(measurements)} | {errors} |"
            )

    if rejected:
        print()
        print("## Rejected reports")
        print()
        for path, reason in rejected:
            print(f"- `{path}`: {reason}")

    failures = root / "failures.tsv"
    if failures.exists() and failures.read_text(encoding="utf-8").strip():
        print()
        print("## Failures")
        print()
        print("```text")
        print(failures.read_text(encoding="utf-8").strip())
        print("```")

    print()
    print(
        "Hosted-runner results are suitable for functional checks and same-job relative regression only. "
        "Use repeated runs on a fixed self-hosted bare-metal runner for publishable absolute comparisons."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
