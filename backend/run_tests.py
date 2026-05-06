"""
run_tests.py — Master test harness orchestrator.

Runs the full closed loop:
  1. Generate adversarial cases
  2. Send to API
  3. Evaluate predictions
  4. Print summary + top failures
  5. Print targeted patch suggestions

Usage:
    python run_tests.py                        # full run
    python run_tests.py --category stt_noise   # single category
    python run_tests.py --rerun                # retest previous failures only
    python run_tests.py --dry-run              # list cases without calling API
    python run_tests.py --no-patches           # skip patch output
"""

import sys
import json
import time
import argparse

from conversation_generator import get_all_cases, get_cases_by_category, get_case_summary
from test_runner             import run_all_tests, run_failures_from_file
from evaluator               import evaluate, save_metrics, compute_metrics, load_results
from improvement_engine      import generate_improvements


# ─────────────────────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        ScamShield  ·  Self-Improving Test Harness  v1        ║
║  Adversarial · Conversation-Aware · Closed-Loop Feedback     ║
╚══════════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────────────────────
#  Dry-run helper
# ─────────────────────────────────────────────────────────────

def dry_run(cases: list):
    """Print all cases with expected verdicts without calling the API."""
    print(f"\n  DRY RUN — listing {len(cases)} cases (no API calls)\n")
    cat_counts = {}
    for c in cases:
        cat_counts[c["category"]] = cat_counts.get(c["category"], 0) + 1
        print(
            f"  [{c['id']:02d}] {c['expected_verdict']:<12s}"
            f"{c['category']:<18s}{c['name']}"
        )
    print(f"\n  Category breakdown:")
    for cat, n in sorted(cat_counts.items()):
        print(f"    {cat:<25s} {n}")
    print()


# ─────────────────────────────────────────────────────────────
#  Compact final summary
# ─────────────────────────────────────────────────────────────

def print_final_summary(metrics: dict, elapsed_total: float):
    sep = "─" * 62
    print(f"\n{sep}")
    print(f"  FINAL SUMMARY")
    print(sep)
    print(f"  Total cases      : {metrics['total']}")
    print(f"  Verdict accuracy : {metrics['accuracy']*100:.1f}%  ({metrics['correct']}/{metrics['valid']})")
    print(f"  Trend accuracy   : {metrics['trend_accuracy']*100:.1f}%")
    print(f"  False positives  : {metrics['fp_count']}  (rate {metrics['fp_rate']*100:.1f}%)")
    print(f"  False negatives  : {metrics['fn_count']}  (rate {metrics['fn_rate']*100:.1f}%)")
    print(f"  Under-detection  : {metrics['under_detection']} (SCAM→SUSPICIOUS)")
    print(f"  Over-detection   : {metrics['over_detection']} (SAFE→SUSPICIOUS)")
    print(f"  API errors       : {metrics['errors']}")
    print(f"  Elapsed total    : {elapsed_total:.1f}s")
    print(sep)

    # Health signal
    acc = metrics["accuracy"]
    fp  = metrics["fp_rate"]
    fn  = metrics["fn_rate"]
    if acc >= 0.90 and fp <= 0.10 and fn <= 0.10:
        health = "✓ HEALTHY  (≥90% accuracy, FP≤10%, FN≤10%)"
    elif acc >= 0.75:
        health = "⚠ MODERATE (≥75% accuracy, some gaps detected)"
    else:
        health = "✗ NEEDS WORK (<75% accuracy — review patches)"

    print(f"\n  System health    : {health}\n")


# ─────────────────────────────────────────────────────────────
#  Top-10 failures pretty printer
# ─────────────────────────────────────────────────────────────

def print_top_failures(metrics: dict, n: int = 10):
    from evaluator import top_failures
    failures = top_failures(metrics, n=n)
    if not failures:
        print("  No failures to report.\n")
        return

    print(f"\n{'─' * 62}")
    print(f"  TOP {n} HIGHEST-IMPACT FAILURES")
    print(f"{'─' * 62}")
    for i, f in enumerate(failures, 1):
        verdict_str = (
            f"expected={f['expected']:<12s}"
            f"got={f['predicted']:<12s}"
            f"conf={f['confidence']}"
        )
        print(f"\n  {i:2d}. {f['name']}")
        print(f"      {verdict_str}")
        print(f"      [{f['category']} / {f['subcategory']}]")
        expl = f["explanation"]
        if len(expl) > 110:
            expl = expl[:107] + "..."
        print(f"      {expl}")
        if f.get("reasons"):
            reason_preview = f["reasons"][0][:85]
            print(f"      API: {reason_preview}")
    print()


# ─────────────────────────────────────────────────────────────
#  Iteration tracker
# ─────────────────────────────────────────────────────────────

HISTORY_FILE = "run_history.json"


def update_history(metrics: dict):
    """Append this run's summary to a history file for trend tracking."""
    entry = {
        "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S"),
        "accuracy":   metrics["accuracy"],
        "fp_rate":    metrics["fp_rate"],
        "fn_rate":    metrics["fn_rate"],
        "total":      metrics["total"],
        "failed":     metrics["incorrect"],
    }
    history = []
    try:
        with open(HISTORY_FILE) as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    history.append(entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)
    print(f"  History updated → {HISTORY_FILE}  (run #{len(history)})")

    # Show trend if we have prior runs
    if len(history) >= 2:
        prev = history[-2]
        curr = history[-1]
        delta_acc = (curr["accuracy"] - prev["accuracy"]) * 100
        delta_fn  = (curr["fn_rate"]  - prev["fn_rate"])  * 100
        delta_fp  = (curr["fp_rate"]  - prev["fp_rate"])  * 100
        sign = lambda x: ("+" if x >= 0 else "") + f"{x:.1f}%"
        print(f"\n  Trend vs previous run:")
        print(f"    Accuracy  {sign(delta_acc)}  |  FP rate {sign(delta_fp)}  |  FN rate {sign(delta_fn)}")


# ─────────────────────────────────────────────────────────────
#  Argument parser
# ─────────────────────────────────────────────────────────────

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="ScamShield Self-Improving Test Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--category",
        default=None,
        help="Run only cases in this category (false_positive|advanced_scam|boundary|evolution|stt_noise|edge)",
    )
    p.add_argument(
        "--rerun",
        action="store_true",
        help="Retest only previously failed cases from test_results.json",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="List cases without calling the API",
    )
    p.add_argument(
        "--no-patches",
        action="store_true",
        dest="no_patches",
        help="Skip improvement engine / patch output",
    )
    p.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top failures to display (default: 10)",
    )
    p.add_argument(
        "--results",
        default="test_results.json",
        help="Path to results JSON (used with --rerun or --eval-only)",
    )
    p.add_argument(
        "--eval-only",
        action="store_true",
        dest="eval_only",
        help="Skip test run; evaluate an existing results file",
    )
    return p


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    args = build_arg_parser().parse_args()
    t0   = time.time()

    # ── Step 0: Case selection ────────────────────────────────
    if args.dry_run:
        cases = (
            get_cases_by_category(args.category)
            if args.category else get_all_cases()
        )
        dry_run(cases)
        summary = get_case_summary()
        print(f"  Corpus: {summary['total']} cases total\n")
        print(f"  Expected verdicts: {summary['by_expected_verdict']}")
        return

    # ── Step 0b: Eval-only shortcut ───────────────────────────
    if args.eval_only:
        print(f"  [eval-only] Loading {args.results}")
        metrics = evaluate(results_file=args.results, top_n=args.top)
        print_top_failures(metrics, n=args.top)
        save_metrics(metrics, "evaluation_report.json")
        if not args.no_patches:
            generate_improvements(results_file=args.results)
        print_final_summary(metrics, time.time() - t0)
        update_history(metrics)
        return

    # ── Step 1: Generate cases ────────────────────────────────
    print("  [1/4] Generating test cases...")
    if args.rerun:
        results_list = run_failures_from_file(args.results)
        results_file = "test_results_rerun.json"
    elif args.category:
        cases        = get_cases_by_category(args.category)
        results_file = f"test_results_{args.category}.json"
        print(f"       Category filter: {args.category}  ({len(cases)} cases)")
        results_list = run_all_tests(cases, output_file=results_file)
    else:
        summary = get_case_summary()
        print(f"       {summary['total']} cases across {len(summary['by_category'])} categories")
        print(f"       Expected verdicts: {summary['by_expected_verdict']}")
        results_file = args.results
        results_list = run_all_tests(output_file=results_file)

    # ── Step 2: Evaluate ──────────────────────────────────────
    print("\n  [2/4] Evaluating results...")
    metrics = compute_metrics(results_list)
    from evaluator import print_report
    print_report(metrics, top_n=args.top)

    # ── Step 3: Top failures ──────────────────────────────────
    print("\n  [3/4] Top failures analysis...")
    print_top_failures(metrics, n=args.top)

    # ── Step 4: Patch suggestions ─────────────────────────────
    if not args.no_patches:
        print("\n  [4/4] Generating patch suggestions...")
        generate_improvements(results_file=results_file)
    else:
        print("\n  [4/4] Patches skipped (--no-patches)")

    # ── Final summary + history ───────────────────────────────
    elapsed = time.time() - t0
    print_final_summary(metrics, elapsed)
    save_metrics(metrics, "evaluation_report.json")
    update_history(metrics)

    # Exit code: non-zero if accuracy below threshold
    threshold = 0.70
    if metrics["accuracy"] < threshold:
        print(f"  [EXIT 1] Accuracy {metrics['accuracy']*100:.1f}% below threshold {threshold*100:.0f}%")
        sys.exit(1)


if __name__ == "__main__":
    main()
