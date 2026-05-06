"""
test_runner.py
Sends every test case to the ScamShield API and records the results.
No external dependencies beyond the stdlib + requests.
"""

import json
import time
import requests
from datetime import datetime
from conversation_generator import get_all_cases

API_URL      = "http://localhost:8000/analyze"
OUTPUT_FILE  = "test_results.json"
TIMEOUT_SECS = 10


# ─────────────────────────────────────────────────────────────
#  Core request helper
# ─────────────────────────────────────────────────────────────

def call_api(messages: list, retries: int = 2) -> dict | None:
    """
    POST messages to /analyze and return the parsed JSON response.
    Returns None on unrecoverable error.
    """
    payload = {"messages": messages}
    for attempt in range(retries + 1):
        try:
            resp = requests.post(API_URL, json=payload, timeout=TIMEOUT_SECS)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            if attempt == 0:
                print(f"    [WARN] Connection refused. Is the API running at {API_URL}?")
            return None
        except requests.exceptions.Timeout:
            print(f"    [WARN] Request timed out (attempt {attempt + 1}/{retries + 1})")
            if attempt < retries:
                time.sleep(1)
        except requests.exceptions.HTTPError as e:
            print(f"    [WARN] HTTP error: {e}")
            return None
        except json.JSONDecodeError:
            print(f"    [WARN] Could not parse API response as JSON")
            return None
    return None


# ─────────────────────────────────────────────────────────────
#  Per-case result builder
# ─────────────────────────────────────────────────────────────

def run_case(case: dict) -> dict:
    """
    Run a single test case against the API.
    Returns a result dict merging expected vs actual.
    """
    raw = call_api(case["messages"])

    if raw is None:
        return {
            "id":                   case["id"],
            "name":                 case["name"],
            "category":             case["category"],
            "subcategory":          case.get("subcategory", ""),
            "explanation":          case.get("explanation", ""),
            "expected_verdict":     case["expected_verdict"],
            "expected_trend":       case["expected_trend"],
            "predicted_verdict":    "ERROR",
            "predicted_trend":      "ERROR",
            "predicted_confidence": "ERROR",
            "reasons":              [],
            "api_error":            True,
            "verdict_correct":      False,
            "trend_correct":        False,
        }

    predicted_verdict    = raw.get("verdict",    "UNKNOWN")
    predicted_trend      = raw.get("trend",      "UNKNOWN")
    predicted_confidence = raw.get("confidence", "UNKNOWN")
    reasons              = raw.get("reasons",    [])

    verdict_correct = predicted_verdict == case["expected_verdict"]
    # Trend: only evaluate if both expected and predicted are real values
    trend_correct = (
        predicted_trend == case["expected_trend"]
        if predicted_trend not in ("UNKNOWN", "ERROR") else False
    )

    return {
        "id":                   case["id"],
        "name":                 case["name"],
        "category":             case["category"],
        "subcategory":          case.get("subcategory", ""),
        "explanation":          case.get("explanation", ""),
        "expected_verdict":     case["expected_verdict"],
        "expected_trend":       case["expected_trend"],
        "predicted_verdict":    predicted_verdict,
        "predicted_trend":      predicted_trend,
        "predicted_confidence": predicted_confidence,
        "reasons":              reasons,
        "raw_response":         raw,
        "api_error":            False,
        "verdict_correct":      verdict_correct,
        "trend_correct":        trend_correct,
    }


# ─────────────────────────────────────────────────────────────
#  Main runner
# ─────────────────────────────────────────────────────────────

def run_all_tests(
    cases: list | None = None,
    output_file: str = OUTPUT_FILE,
    verbose: bool = True,
) -> list:
    """
    Run all cases, print live progress, save results to JSON.
    Returns the list of result dicts.
    """
    if cases is None:
        cases = get_all_cases()

    results   = []
    passed    = 0
    failed    = 0
    errors    = 0
    start_ts  = time.time()

    print(f"\n{'=' * 60}")
    print(f" ScamShield Test Runner")
    print(f" Target : {API_URL}")
    print(f" Cases  : {len(cases)}")
    print(f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}\n")

    for case in cases:
        result = run_case(case)
        results.append(result)

        status_symbol = "✓" if result["verdict_correct"] else "✗"
        trend_symbol  = "~" if result["trend_correct"]   else "≠"

        if result["api_error"]:
            status = "ERROR"
            errors += 1
        elif result["verdict_correct"]:
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1

        if verbose:
            print(
                f"  [{result['id']:02d}] {status_symbol} {status:<5s} {trend_symbol}trend "
                f"| {result['name']:<48s} "
                f"expected={result['expected_verdict']:<12s} "
                f"got={result['predicted_verdict']:<12s} "
                f"conf={result['predicted_confidence']}"
            )

    elapsed = time.time() - start_ts

    # ── Summary header ────────────────────────────────────────
    total = len(cases)
    print(f"\n{'─' * 60}")
    print(f" Results: {passed}/{total} passed  |  {failed} failed  |  {errors} errors")
    print(f" Elapsed: {elapsed:.1f}s  (~{elapsed/total:.2f}s per case)")
    print(f"{'─' * 60}\n")

    # ── Persist to disk ───────────────────────────────────────
    output = {
        "meta": {
            "run_at":   datetime.now().isoformat(),
            "api_url":  API_URL,
            "total":    total,
            "passed":   passed,
            "failed":   failed,
            "errors":   errors,
            "elapsed_s": round(elapsed, 2),
        },
        "results": results,
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"  Results saved → {output_file}")
    return results


# ─────────────────────────────────────────────────────────────
#  Targeted re-run helpers
# ─────────────────────────────────────────────────────────────

def run_category(category: str, output_file: str | None = None) -> list:
    """Run only cases matching a given category."""
    from conversation_generator import get_cases_by_category
    cases = get_cases_by_category(category)
    out   = output_file or f"test_results_{category}.json"
    print(f"\n[Targeted run] Category={category}  ({len(cases)} cases)")
    return run_all_tests(cases, output_file=out)


def run_failures_from_file(results_file: str = OUTPUT_FILE) -> list:
    """Reload a previous run and re-test only the failed cases."""
    from conversation_generator import get_all_cases
    all_cases = {c["name"]: c for c in get_all_cases()}
    with open(results_file) as f:
        data = json.load(f)
    failed_names = [
        r["name"] for r in data["results"]
        if not r["verdict_correct"] and not r["api_error"]
    ]
    cases_to_retry = [all_cases[n] for n in failed_names if n in all_cases]
    print(f"\n[Re-run] Retesting {len(cases_to_retry)} previously failed cases")
    return run_all_tests(cases_to_retry, output_file="test_results_rerun.json")


if __name__ == "__main__":
    run_all_tests()
