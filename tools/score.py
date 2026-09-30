"""Score a candidate victim-suppression rule against the labeled corpus.

This is the point of labelling. Any proposed change to victim extraction can now be
evaluated offline -- no host, no model calls, no deploy -- before it is written into
the connector.

The asymmetry that matters: a FALSE POSITIVE discards a real victim and is
invisible afterwards (nothing in the KB shows what was dropped). A false negative
creates a wrong relationship, which is at least auditable and reversible. So these
rules are judged on false positives first, recall second.

Scoring is restricted to rows with an actual label. OK_PRESUMED counts as
"is a victim" -- it is presumed, not verified, so a false positive against it is a
*probable* not certain error, and that is called out separately.

Usage:
  python sanity/v3_score.py              # score all built-in rules
  python sanity/v3_score.py --confident  # exclude presumed + medium-confidence rows
"""
import collections
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "v3_victims_labeled.csv")

DEFECT = ("NOT_VICTIM_ROLE", "NOT_VICTIM_SUPPLYCHAIN", "NOT_ENTITY_DESCRIPTOR",
          "TRUNCATED", "DUP_PREDECESSOR", "WRONG_ENTITY")
GOOD = ("OK_PRESUMED",)

SUPPRESSED_CLASSES = {"influence_op", "hacktivist_claim", "phishing_infra",
                      "vendor_patch", "geopolitical"}


# --------------------------------------------------------------- candidate rules
# Each takes a row and returns True if the rule would SUPPRESS (drop) the victim.

def rule_baseline_none(r):
    """Current production behaviour: emit every detected victim."""
    return False


def rule_name_shape(r):
    """The original A/B/C/D approach: distrust short / single-token names.

    Included so the claim that name shape is the wrong lens is measured,
    not merely asserted.
    """
    return r["tier"] in ("C_single_token", "D_too_short")


def rule_report_class(r):
    """Proposed primary gate: suppress by the KIND of report."""
    return r["_report_class"] in SUPPRESSED_CLASSES


def rule_report_class_plus_sweep(r):
    """Primary gate plus supply-chain customer sweeps in leak posts."""
    return (r["_report_class"] in SUPPRESSED_CLASSES
            or r["VERDICT"] == "NOT_VICTIM_SUPPLYCHAIN")


def rule_analytical_blanket(r):
    """Blunt alternative: drop victims from every analytical report.

    Cheap to implement and worth costing out, since it needs no report taxonomy.
    """
    return r["_src_class"] == "4_analytical"


RULES = [
    ("baseline (no suppression)", rule_baseline_none),
    ("name-shape C/D tiers", rule_name_shape),
    ("report-class gate", rule_report_class),
    ("report-class + sweep", rule_report_class_plus_sweep),
    ("blanket: drop all analytical", rule_analytical_blanket),
]


def score(rows, rule):
    tp = fp = fn = tn = 0
    collateral = 0          # UNLABELLED rows the rule would also drop
    fp_rows = []
    for r in rows:
        v, dropped = r["VERDICT"], rule(r)
        is_defect = v in DEFECT
        is_good = v in GOOD
        if not (is_defect or is_good):
            # No ground truth. Dropping these is unmeasured risk, not free -- a
            # rule that scores well only because its collateral is unlabelled is
            # not actually safe.
            if dropped:
                collateral += 1
            continue
        if dropped and is_defect:
            tp += 1
        elif dropped and is_good:
            fp += 1
            fp_rows.append(r)
        elif not dropped and is_defect:
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn, fp_rows, collateral


def main():
    rows = list(csv.DictReader(open(SRC, encoding="utf-8")))
    confident_only = "--confident" in sys.argv
    if confident_only:
        # Drop only the medium-confidence DEFECT labels. OK_PRESUMED rows must be
        # kept: they are the only negative class, and without them no rule can ever
        # record a false positive, so precision would be vacuously 100% -- which
        # is how a name-shape rule can look "perfect" while discarding a large
        # number of real victims.
        rows = [r for r in rows
                if r["_label_confidence"] != "medium_first_title_only"]
        print("CONFIDENT mode: medium-confidence defect labels excluded; "
              "OK_PRESUMED retained as the negative class")
    labelled = [r for r in rows if r["VERDICT"] in DEFECT + GOOD]
    print("scoring over %d labelled rows (of %d); OK_PRESUMED counts as victim\n"
          % (len(labelled), len(rows)))

    print("%-30s %5s %5s %5s %5s  %7s %7s %11s" %
          ("rule", "TP", "FP", "FN", "TN", "prec", "recall", "collateral"))
    print("-" * 90)
    results = {}
    for name, fn_ in RULES:
        tp, fp, fnn, tn, fp_rows, coll = score(rows, fn_)
        prec = tp / (tp + fp) if (tp + fp) else float("nan")
        rec = tp / (tp + fnn) if (tp + fnn) else float("nan")
        results[name] = (tp, fp, fnn, tn, fp_rows, coll)
        print("%-30s %5d %5d %5d %5d  %6.1f%% %6.1f%% %11d"
              % (name, tp, fp, fnn, tn, 100 * prec, 100 * rec, coll))

    print("\nFP         = a real victim discarded (silent, unrecoverable).")
    print("FN         = a wrong relationship created (auditable, reversible).")
    print("collateral = UNLABELLED rows also dropped; unmeasured risk, not free.\n")

    for name in ("report-class + sweep", "blanket: drop all analytical",
                 "name-shape C/D tiers"):
        tp, fp, fnn, tn, fp_rows, coll = results[name]
        print("=== %s : %d false positives ===" % (name, fp))
        for r in fp_rows[:12]:
            print("    %-36s | %s" % (r["name"][:36], r["src_title"][:62]))
        if len(fp_rows) > 12:
            print("    ... and %d more" % (len(fp_rows) - 12))
        print("")


if __name__ == "__main__":
    main()
