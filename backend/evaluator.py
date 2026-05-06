"""
evaluator.py
Analyses test_results.json and produces:
  - Overall accuracy, FP rate, FN rate
  - Confidence calibration errors
  - Trend accuracy
  - Failure groups mapped to detector weakness categories
  - Top-N worst failures with root-cause hints
"""

import json
from collections import defaultdict, Counter
from typing import Any

RESULTS_FILE = "test_results.json"


# ─────────────────────────────────────────────────────────────
#  Loaders
# ─────────────────────────────────────────────────────────────

def load_results(path: str = RESULTS_FILE) -> list:
    with open(path) as f:
        data = json.load(f)
    return data["results"]


# ─────────────────────────────────────────────────────────────
#  Core Metrics
# ─────────────────────────────────────────────────────────────

def compute_metrics(results: list) -> dict:
    """
    Compute overall accuracy, FP rate, FN rate, SUSPICIOUS accuracy,
    trend accuracy, and confidence calibration.
    """
    total        = len(results)
    valid        = [r for r in results if not r["api_error"]]
    error_count  = total - len(valid)

    # ── Verdict accuracy ──────────────────────────────────────
    correct    = [r for r in valid if r["verdict_correct"]]
    incorrect  = [r for r in valid if not r["verdict_correct"]]
    accuracy   = len(correct) / len(valid) if valid else 0.0

    # ── False Positives: expected SAFE/SUSPICIOUS, got SCAM ──
    fp = [
        r for r in valid
        if r["expected_verdict"] in ("SAFE", "SUSPICIOUS")
        and r["predicted_verdict"] == "SCAM"
    ]

    # ── False Negatives: expected SCAM, got SAFE/SUSPICIOUS ──
    fn = [
        r for r in valid
        if r["expected_verdict"] == "SCAM"
        and r["predicted_verdict"] != "SCAM"
    ]

    # ── PATCH: explicit SCAM→SAFE and SCAM→SUSPICIOUS tracking ──
    scam_to_safe = [
        r for r in valid
        if r["expected_verdict"] == "SCAM"
        and r["predicted_verdict"] == "SAFE"
    ]
    scam_to_suspicious = [
        r for r in valid
        if r["expected_verdict"] == "SCAM"
        and r["predicted_verdict"] == "SUSPICIOUS"
    ]

    # ── Under-detection: expected SCAM, got SUSPICIOUS ───────
    under = [
        r for r in valid
        if r["expected_verdict"] == "SCAM"
        and r["predicted_verdict"] == "SUSPICIOUS"
    ]

    # ── Over-detection: expected SAFE, got SUSPICIOUS ────────
    over = [
        r for r in valid
        if r["expected_verdict"] == "SAFE"
        and r["predicted_verdict"] == "SUSPICIOUS"
    ]

    total_scam_expected  = sum(1 for r in valid if r["expected_verdict"] == "SCAM")
    total_safe_expected  = sum(1 for r in valid if r["expected_verdict"] in ("SAFE", "SUSPICIOUS"))

    fp_rate = len(fp) / total_safe_expected if total_safe_expected else 0.0
    fn_rate = len(fn) / total_scam_expected if total_scam_expected else 0.0

    # ── Trend accuracy ────────────────────────────────────────
    trend_eligible = [r for r in valid if r["predicted_trend"] not in ("UNKNOWN", "ERROR")]
    trend_correct  = [r for r in trend_eligible if r["trend_correct"]]
    trend_accuracy = len(trend_correct) / len(trend_eligible) if trend_eligible else 0.0

    # ── Confidence calibration ────────────────────────────────
    conf_errors = _compute_confidence_errors(valid)

    # ── Accuracy by category ──────────────────────────────────
    cat_stats = _accuracy_by_field(valid, "category")
    sub_stats = _accuracy_by_field(valid, "subcategory")

    return {
        "total":                total,
        "valid":                len(valid),
        "errors":               error_count,
        "correct":              len(correct),
        "incorrect":            len(incorrect),
        "accuracy":             round(accuracy,   4),
        "fp_count":             len(fp),
        "fn_count":             len(fn),
        "scam_to_safe_count":   len(scam_to_safe),
        "scam_to_suspicious_count": len(scam_to_suspicious),
        "under_detection":      len(under),
        "over_detection":       len(over),
        "fp_rate":              round(fp_rate,    4),
        "fn_rate":              round(fn_rate,    4),
        "trend_accuracy":       round(trend_accuracy, 4),
        "confidence_errors":    conf_errors,
        "by_category":          cat_stats,
        "by_subcategory":       sub_stats,
        "false_positives":      [_slim(r) for r in fp],
        "false_negatives":      [_slim(r) for r in fn],
        "scam_to_safe":         [_slim(r) for r in scam_to_safe],
        "scam_to_suspicious":   [_slim(r) for r in scam_to_suspicious],
        "under_detection_list": [_slim(r) for r in under],
        "over_detection_list":  [_slim(r) for r in over],
        "all_failures":         [_slim(r) for r in incorrect],
    }


def _slim(r: dict) -> dict:
    """Return a compact failure record."""
    return {
        "id":           r["id"],
        "name":         r["name"],
        "category":     r["category"],
        "subcategory":  r["subcategory"],
        "expected":     r["expected_verdict"],
        "predicted":    r["predicted_verdict"],
        "confidence":   r["predicted_confidence"],
        "trend_exp":    r["expected_trend"],
        "trend_got":    r["predicted_trend"],
        "explanation":  r["explanation"],
        "reasons":      r.get("reasons", [])[:3],
    }


def _accuracy_by_field(results: list, field: str) -> dict:
    stats = defaultdict(lambda: {"total": 0, "correct": 0})
    for r in results:
        key = r.get(field, "unknown")
        stats[key]["total"]   += 1
        if r["verdict_correct"]:
            stats[key]["correct"] += 1
    return {
        k: {
            "total":    v["total"],
            "correct":  v["correct"],
            "accuracy": round(v["correct"] / v["total"], 3),
        }
        for k, v in sorted(stats.items())
    }


def _compute_confidence_errors(results: list) -> list:
    """
    Flag cases where confidence doesn't match the verdict quality.
      SCAM  + LOW confidence  → under-confident on real threat
      SAFE  + LOW confidence  → under-confident on clear safe
      wrong + HIGH confidence → over-confident on wrong answer
    """
    errors = []
    for r in results:
        pred_v = r["predicted_verdict"]
        pred_c = r["predicted_confidence"]
        exp_v  = r["expected_verdict"]
        correct = r["verdict_correct"]

        issue = None
        if pred_v == "SCAM" and pred_c == "LOW":
            issue = "LOW confidence on predicted SCAM — detector uncertain about a threat"
        elif pred_v == "SAFE" and pred_c == "LOW":
            issue = "LOW confidence on SAFE — detector unsure even about benign input"
        elif not correct and pred_c == "HIGH":
            issue = f"HIGH confidence on WRONG verdict ({pred_v} vs expected {exp_v})"

        if issue:
            errors.append({
                "name":       r["name"],
                "category":   r["category"],
                "issue":      issue,
                "predicted":  pred_v,
                "expected":   exp_v,
                "confidence": pred_c,
            })
    return errors


# ─────────────────────────────────────────────────────────────
#  Weakness Grouping
# ─────────────────────────────────────────────────────────────

# Maps subcategory / failure characteristics → weakness bucket
_WEAKNESS_MAP = {
    "friend_money":          "FALSE_POSITIVE: friend/family money",
    "family_money":          "FALSE_POSITIVE: friend/family money",
    "real_bank_alert":       "FALSE_POSITIVE: legitimate bank alert",
    "office_payment":        "FALSE_POSITIVE: workplace payment",
    "meta_discussion":       "FALSE_POSITIVE: meta/awareness context",
    "familiarity":           "SCAM_MISS: fake familiarity pattern",
    "authority":             "SCAM_MISS: authority impersonation",
    "emotional":             "SCAM_MISS: emotional manipulation",
    "corporate":             "SCAM_MISS: corporate/invoice scam",
    "flattery":              "SCAM_MISS: lottery/flattery bait",
    "phonetic":              "STT_MISS: phonetic bypass",
    "broken_grammar":        "STT_MISS: broken grammar",
    "hinglish":              "STT_MISS: Hinglish/regional language",
    "obfuscation":           "STT_MISS: character obfuscation",
    "filler":                "STT_MISS: filler word injection",
    "vague":                 "BOUNDARY: vague/incomplete signal",
    "authority_no_demand":   "BOUNDARY: authority without demand",
    "mixed_signals":         "BOUNDARY: mixed safe+risky signals",
    "safe_to_scam":          "EVOLUTION: SAFE→SCAM transition missed",
    "scam_to_safe":          "EVOLUTION: DE-ESCALATION not tracked",
    "escalating":            "EVOLUTION: gradual escalation missed",
    "stable_scam":           "EVOLUTION: stable high-risk missed",
    "denial_tactic":         "SCAM_MISS: denial-as-amplifier",
    "reverse_flow":          "FALSE_POSITIVE: money flowing to user",
    "minimal":               "EDGE: minimal/single-message",
    "context_dependent":     "FALSE_POSITIVE: context-dependent keyword",
    "authority_legitimate":  "BOUNDARY: real authority, no demand",
}


def group_failures_by_weakness(failures: list) -> dict:
    """
    Organise failures into named weakness buckets with examples.
    """
    buckets: dict[str, list] = defaultdict(list)
    for f in failures:
        sub   = f.get("subcategory", "unknown")
        label = _WEAKNESS_MAP.get(sub, f"UNCATEGORISED: {sub}")
        buckets[label].append(f)

    # Sort by bucket size desc
    return dict(sorted(buckets.items(), key=lambda x: -len(x[1])))


# ─────────────────────────────────────────────────────────────
#  Top-N Failures
# ─────────────────────────────────────────────────────────────

def top_failures(metrics: dict, n: int = 10) -> list:
    """
    Return the N most impactful failures, ranked by:
      1. FN (missed scam)   — highest harm
      2. FP with HIGH conf  — most misleading
      3. FN with HIGH conf  — most dangerous miss
    """
    failures = metrics["all_failures"]

    def _rank(f):
        is_fn = f["expected"] == "SCAM" and f["predicted"] != "SCAM"
        conf_weight = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(f["confidence"], 0)
        return (int(is_fn) * 10) + conf_weight

    return sorted(failures, key=_rank, reverse=True)[:n]


# ─────────────────────────────────────────────────────────────
#  Pretty Printing
# ─────────────────────────────────────────────────────────────

def print_report(metrics: dict, top_n: int = 10):
    sep = "═" * 62

    print(f"\n{sep}")
    print(f"  SCAMSHIELD EVALUATION REPORT")
    print(sep)

    print(f"\n  {'Total cases':<30s} {metrics['total']}")
    print(f"  {'Valid (no API error)':<30s} {metrics['valid']}")
    print(f"  {'API errors':<30s} {metrics['errors']}")
    print(f"\n  {'Overall verdict accuracy':<30s} {metrics['accuracy']*100:.1f}%")
    print(f"  {'Trend accuracy':<30s} {metrics['trend_accuracy']*100:.1f}%")
    print(f"\n  {'False positives (SAFE→SCAM)':<30s} {metrics['fp_count']}  (FP rate {metrics['fp_rate']*100:.1f}%)")
    print(f"  {'False negatives (SCAM missed)':<30s} {metrics['fn_count']}  (FN rate {metrics['fn_rate']*100:.1f}%)")
    print(f"  {'  → SCAM classified as SAFE':<30s} {metrics.get('scam_to_safe_count', 'N/A')}")
    print(f"  {'  → SCAM classified as SUSP':<30s} {metrics.get('scam_to_suspicious_count', 'N/A')}")
    print(f"  {'Under-detection (SCAM→SUSP)':<30s} {metrics['under_detection']}")
    print(f"  {'Over-detection  (SAFE→SUSP)':<30s} {metrics['over_detection']}")

    # ── By category ───────────────────────────────────────────
    print(f"\n{'─' * 62}")
    print("  ACCURACY BY CATEGORY")
    print(f"{'─' * 62}")
    for cat, s in metrics["by_category"].items():
        bar = "█" * int(s["accuracy"] * 20)
        print(f"  {cat:<25s} {s['accuracy']*100:5.1f}%  [{bar:<20s}]  {s['correct']}/{s['total']}")

    # ── By subcategory ────────────────────────────────────────
    print(f"\n{'─' * 62}")
    print("  ACCURACY BY SUBCATEGORY")
    print(f"{'─' * 62}")
    for sub, s in sorted(metrics["by_subcategory"].items(), key=lambda x: x[1]["accuracy"]):
        bar   = "█" * int(s["accuracy"] * 20)
        flag  = " ⚠" if s["accuracy"] < 0.5 else ""
        print(f"  {sub:<30s} {s['accuracy']*100:5.1f}%  [{bar:<20s}]  {s['correct']}/{s['total']}{flag}")

    # ── Confidence errors ─────────────────────────────────────
    conf_errors = metrics["confidence_errors"]
    if conf_errors:
        print(f"\n{'─' * 62}")
        print(f"  CONFIDENCE CALIBRATION ISSUES  ({len(conf_errors)} cases)")
        print(f"{'─' * 62}")
        for e in conf_errors:
            print(f"  [{e['name'][:45]:<45s}]")
            print(f"       {e['issue']}")

    # ── Weakness buckets ──────────────────────────────────────
    weakness_map = group_failures_by_weakness(metrics["all_failures"])
    if weakness_map:
        print(f"\n{'─' * 62}")
        print(f"  FAILURE WEAKNESS BUCKETS  ({sum(len(v) for v in weakness_map.values())} failures)")
        print(f"{'─' * 62}")

        # PATCH: highlight top 5 failure patterns
        top5 = list(weakness_map.items())[:5]
        print(f"\n  TOP 5 FAILURE PATTERNS:")
        for rank, (label, cases) in enumerate(top5, 1):
            print(f"    {rank}. [{len(cases)} failures] {label}")
        print()

        for label, cases in weakness_map.items():
            print(f"\n  [{len(cases):2d} failure(s)]  {label}")
            for c in cases[:3]:
                print(f"    • {c['name']}")
                print(f"      expected={c['expected']:<12s} predicted={c['predicted']}")
            if len(cases) > 3:
                print(f"    ... and {len(cases)-3} more")

    # ── Top failures ──────────────────────────────────────────
    top = top_failures(metrics, n=top_n)
    if top:
        print(f"\n{'─' * 62}")
        print(f"  TOP {top_n} HIGHEST-IMPACT FAILURES")
        print(f"{'─' * 62}")
        for i, f in enumerate(top, 1):
            print(f"\n  {i:2d}. {f['name']}")
            print(f"      Category   : {f['category']} / {f['subcategory']}")
            print(f"      Expected   : {f['expected']:<10s} Predicted: {f['predicted']:<10s} Conf: {f['confidence']}")
            print(f"      Explanation: {f['explanation'][:100]}...")
            if f["reasons"]:
                print(f"      API reasons: {f['reasons'][0][:90]}")

    print(f"\n{sep}\n")


# ─────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────

def evaluate(results_file: str = RESULTS_FILE, top_n: int = 10) -> dict:
    """Load, compute, print, and return full metrics dict."""
    results = load_results(results_file)
    metrics = compute_metrics(results)
    print_report(metrics, top_n=top_n)
    return metrics


def save_metrics(metrics: dict, path: str = "evaluation_report.json"):
    """Persist the metrics dict to disk."""
    with open(path, "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    print(f"  Metrics saved → {path}")


if __name__ == "__main__":
    m = evaluate()
    save_metrics(m)