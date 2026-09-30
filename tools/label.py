"""Write ground-truth VERDICT/NOTE into the victim corpus -> victims_labeled.csv

WHY THIS EXISTS: an earlier review pass produced
per-row judgements that lived only in terminal output and were lost. Without
persisted labels there is no way to score a candidate fix, so every proposed
change to victim extraction is an argument rather than a measurement.

This labels what can be labelled DEFENSIBLY and refuses to guess on the rest.
Two principles:

  1. Label at the level the error occurs. Role conflation is a property of the
     REPORT, not the name -- an influence-network report is wrong about every org
     it names, so all its rows label together. That is why these labels are
     trustworthy despite being machine-generated.

  2. Never invent a label to reach full coverage. Rows needing human judgement get
     REVIEW and are listed for a person. A wrong label is worse than no label
     because it silently corrupts the score of every future fix.

Detector calibration notes (all checked against the real strings first):
  - Collective-noun keyword matching for "generic descriptor" was tried and
    ABANDONED: it flags 'Government of Astora', 'Kestrel Bank' and
    'Royal Coastal Rescue Institution', which are all legitimate named orgs.
    Only 2 rows are genuinely generic, so they are enumerated explicitly.
  - Short-name / acronym shape is NOT a defect signal. WELT, ZDF, RTL, BBC, AFP
    are real organisations; they are wrong only in ROLE.
  - Trailing-dangle truncation detection hit 3/3 with zero false positives.
  - "emitted org shares no token with the claimed victim" is NOT by itself a
     defect: it fires on correct domain->legal-name expansion (erac-calais.example
     -> 'Ecole Regionale des Arts de Calais'). Only a post emitting >=2 unrelated
     orgs indicates a supply-chain customer sweep.

THE CORPUS IS NOT IN THIS REPOSITORY. It is real breach reporting naming real
organisations, so it is not publishable, and a fabricated substitute would produce
labels that look like ground truth and are not. This file is published as the
METHODOLOGY -- how to label defensibly, what not to guess at, and why the labels
are trustworthy despite being machine-generated. Point it at your own corpus in the
schema described in `expected_schema()` below.

Usage:
  python tools/label.py                 # label the corpus
  python tools/label.py --report        # also list rows awaiting human judgement
  python tools/label.py --audit         # list every title each suppression matched
  python tools/label.py --schema        # print the expected input columns
"""
import collections
import csv
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get("VICTIM_CORPUS") or os.path.join(
    HERE, "..", "victims_windowed.csv")
OUT = os.environ.get("VICTIM_CORPUS_LABELLED") or os.path.join(
    HERE, "..", "victims_labeled.csv")


def expected_schema():
    """Input columns this expects, so the tool is usable against another corpus."""
    return {
        "name": "the organisation name the connector emitted as a victim",
        "src_title": "title of the report it was emitted from (drives the "
                     "report-class label; the single most important column)",
        "decisions": "how many times this name was emitted across the corpus; "
                     "used only to mark label confidence. Optional, defaults 1.",
    }


def _load(path):
    """Read the corpus, or explain precisely what is missing and stop.

    A bare FileNotFoundError traceback here would be a poor welcome for anyone who
    cloned the repo and ran the tool, since the file is absent BY DESIGN.
    """
    if not os.path.exists(path):
        print(f"corpus not found: {path}\n", file=sys.stderr)
        print("This is expected on a fresh clone -- the corpus is real breach "
              "reporting\nabout real organisations and is deliberately not "
              "published. See the\nmodule docstring.\n", file=sys.stderr)
        print("To run this against your own corpus, set VICTIM_CORPUS to a CSV "
              "with:", file=sys.stderr)
        for col, why in expected_schema().items():
            print(f"    {col:12} {why}", file=sys.stderr)
        raise SystemExit(2)
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    if not rows:
        print(f"corpus is empty: {path}", file=sys.stderr)
        raise SystemExit(2)
    missing = [c for c in ("name", "src_title") if c not in rows[0]]
    if missing:
        print(f"corpus is missing required column(s): {', '.join(missing)}",
              file=sys.stderr)
        print("run with --schema to see what is expected", file=sys.stderr)
        raise SystemExit(2)
    return rows

# ---------------------------------------------------------------- source class
LEAK = re.compile(
    r"has published a new victim|published a new victim|"
    r"credential leak|data leak site|leak site|^\"|new victim:", re.I)
DISCLOSURE = re.compile(
    r"\breports?\b.*\b(breach|incident|unauthori[sz]ed|ransomware|attack|outage|"
    r"compromise|exposure|fraudulent|fraud|leak|scam|"
    r"personal information|data)\b|"
    r"\bdiscloses?\b|"
    r"\bconfirms?\b.*\b(breach|incident|attack)|\bnotifies\b|\bdata breach\b", re.I)


def src_class(title):
    t = title or ""
    if not t.strip():
        return "3_no_title"
    if LEAK.search(t):
        return "1_leak_post"
    if DISCLOSURE.search(t):
        return "2_disclosure"
    return "4_analytical"


# ------------------------------------------------- analytical report sub-class
INFLUENCE = re.compile(
    # NOTE: deliberately no named operations here. An earlier version listed one
    # specific influence operation by name, which tuned the pattern to one
    # feed's wording without adding recall the generic terms below don't already
    # give. Keep this vocabulary generic so it ports to another corpus.
    r"influence network|influence operation|fabricated|"
    r"testimonial|disinformation|propaganda|Russian State Media|"
    r"political content|midterm|election|inauthentic", re.I)
PHISHING = re.compile(
    r"phishing domain|phishing|typosquat|spoof|impersonat|naming convention|lure",
    re.I)
HACKTIVIST = re.compile(
    r"hacktivist|claims? (alleged )?attack|claims to target|threatens", re.I)

# Vendor patch advisories. The named org SHIPS the patched product; it is not a
# victim, and these titles usually state outright that nothing was exploited.
VENDOR_PATCH = re.compile(
    r"patch(es|ed)?\b.*\bCVE-|"
    r"no active exploitation|"
    r"\b(fixes|addresses)\b.*\bCVE-", re.I)

# Geopolitical / physical-threat products, which some commercial feeds publish
# in volume alongside cyber reporting. These
# assert no cyber compromise at all -- missile strikes, diplomatic expulsions,
# asset seizures, censorship regimes. Orgs named are at RISK or are geopolitical
# actors. Enumerated rather than inferred, because "attack" alone is ambiguous.
GEOPOLITICAL = re.compile(
    r"expulsion of|diplomatic installation|strategic miscalculation|"
    r"houthi (attack|strikes)|houthis attack|missile capabilit|"
    r"active deterrence|violent extremist attack|seizes assets|"
    r"tightening internet controls|internet controls|bi-weekly digest|"
    r"multi-front threat|broadens threat|expand campaign|"
    r"pose strategic security|escalates threat of|"
    r"raise(s)? (escalation|risks) ", re.I)


# Guard against suppressing real intrusion reporting. Influence/phishing wording
# often describes the LURE of a genuine malware campaign ("Fabricated Allegations
# Used to Deliver a Commodity RAT") -- that is an intrusion report with real
# targets, not an influence operation. Delivery/implant vocabulary wins.
INTRUSION_OVERRIDE = re.compile(
    r"\b(RAT|backdoor|stealer|implant|webshell|loader|downloader|dropper|"
    r"ransomware|malware|payload|deliver(s|ed|y)?|deploy(s|ed)?|"
    r"exploit(s|ed|ing)?|zero-day|CVE-\d|infostealer|trojan)\b", re.I)


def report_class(title):
    t = title or ""
    if INTRUSION_OVERRIDE.search(t) and not VENDOR_PATCH.search(t):
        return "intrusion_reporting"
    if INFLUENCE.search(t):
        return "influence_op"
    if PHISHING.search(t):
        return "phishing_infra"
    if HACKTIVIST.search(t):
        return "hacktivist_claim"
    if VENDOR_PATCH.search(t):
        return "vendor_patch"
    if GEOPOLITICAL.search(t):
        return "geopolitical"
    return "intrusion_reporting"


# ----------------------------------------------------- supply-chain sweep calc
CLAIM = re.compile(r"(?:has )?published a new victim:\s*(.+)$", re.I)
STOP = {"the", "and", "inc", "llc", "ltd", "com", "group", "corp", "company",
        "limited", "gmbh", "srl", "sas", "holdings", "ltda"}


def toks(s):
    s = re.sub(r"\(.*?\)", " ", s or "").lower()
    s = re.sub(r"\.(com|org|net|io|gov|edu|fr|fi|ht|mm)\b", " ", s)
    return set(t for t in re.split(r"[^a-z0-9]+", s) if len(t) > 2) - STOP


def related(claimed, got):
    if not claimed or not got:
        return True
    if claimed & got:
        return True
    return any(c in g or g in c for c in claimed for g in got
               if len(c) > 3 and len(g) > 3)


# ---------------------------------------------------- enumerated small classes
# Kept as explicit lists because the population is small enough to read and a
# regex here would misfire on legitimate names (see module docstring).
DESCRIPTOR = {
    "Astoran government organization": "generic category, not a named org",
    "Kalindan opposition and dissidents": "a population, not an organisation",
    "Luxury Safari Lodge near Redhill Game Reserve":
        "description of the victim, not its name (victim was Redhill Caves Lodge)",
}
TRUNCATED = {
    "CREATIVE GARDENS & L": "name cut off mid-token",
    "St Alban the Martyr Roman Catholic":
        "missing head noun (Church/School/Parish)",
    "Coastal Rescue Diving and Salvage": "missing 'Command'",
}
DUP_PREDECESSOR = {
    "Ashford Institute of Technology":
        "predecessor of Institute of Science Ashford (merger) already emitted",
    "Ashford Medical and Dental University":
        "predecessor of Institute of Science Ashford (merger) already emitted",
}
WRONG_ENTITY = {
    "Northern Gymnastics Federation":
        "wrong sport; source is a table tennis association disclosure",
}

ROLE_NOTE = {
    "influence_op": "impersonated / amplified by an influence network, not breached",
    "phishing_infra": "brand spoofed in phishing infrastructure, not breached",
    "hacktivist_claim": "unverified adversary claim, not a confirmed compromise",
    "vendor_patch": "vendor of the patched product; advisory asserts no compromise",
    "geopolitical": "geopolitical/physical-threat report; no cyber compromise asserted",
}


def main():
    if "--schema" in sys.argv:
        print("expected input columns:")
        for col, why in expected_schema().items():
            print(f"  {col:12} {why}")
        return
    rows = _load(SRC)

    # pre-compute which leak posts are customer sweeps
    nomatch = collections.defaultdict(list)
    for r in rows:
        m = CLAIM.search(r["src_title"] or "")
        if not m:
            continue
        if not related(toks(m.group(1)), toks(r["name"])):
            nomatch[r["src_title"]].append(r["name"])
    sweep_titles = {t for t, v in nomatch.items() if len(v) >= 2}
    single_titles = {t for t, v in nomatch.items() if len(v) == 1}

    for r in rows:
        sc = src_class(r["src_title"])
        rc = report_class(r["src_title"]) if sc == "4_analytical" else ""
        name, title = r["name"], r["src_title"]
        verdict = note = ""

        # precedence: name-level defects are stated even inside a bad report,
        # because they need different fixes.
        if name in DESCRIPTOR:
            verdict, note = "NOT_ENTITY_DESCRIPTOR", DESCRIPTOR[name]
        elif name in TRUNCATED:
            verdict, note = "TRUNCATED", TRUNCATED[name]
        elif name in DUP_PREDECESSOR:
            verdict, note = "DUP_PREDECESSOR", DUP_PREDECESSOR[name]
        elif name in WRONG_ENTITY:
            verdict, note = "WRONG_ENTITY", WRONG_ENTITY[name]
        elif sc == "4_analytical" and rc in ROLE_NOTE:
            verdict, note = "NOT_VICTIM_ROLE", ROLE_NOTE[rc]
        elif title in sweep_titles and name in nomatch[title]:
            verdict = "NOT_VICTIM_SUPPLYCHAIN"
            note = ("customer of the named victim, not a victim; post named %r"
                    % CLAIM.search(title).group(1)[:50])
        elif title in single_titles and name in nomatch[title]:
            verdict = "REVIEW_EXPANSION"
            note = ("likely correct domain->legal-name expansion of %r - confirm"
                    % CLAIM.search(title).group(1)[:50])
        elif sc in ("1_leak_post", "2_disclosure"):
            verdict = "OK_PRESUMED"
            note = "source names the victim explicitly; not individually verified"
        else:
            verdict = "REVIEW"
            note = "intrusion report, needs human judgement on role"

        r["VERDICT"], r["NOTE"] = verdict, note
        r["_src_class"], r["_report_class"] = sc, rc

        # Label confidence. `src_title` records only the FIRST context a name was
        # seen in, so a name emitted from several reports may also have appeared in
        # a report of a DIFFERENT class than the one labelled here. Report-level
        # labels on those rows therefore rest on partial evidence, and are marked
        # medium rather than high.
        if verdict in ("REVIEW", "REVIEW_EXPANSION"):
            conf = "unlabelled"
        elif verdict == "OK_PRESUMED":
            conf = "presumed"
        elif name in DESCRIPTOR or name in TRUNCATED or name in DUP_PREDECESSOR \
                or name in WRONG_ENTITY:
            conf = "high_enumerated"
        elif int(r.get("decisions") or 1) > 1:
            conf = "medium_first_title_only"
        else:
            conf = "high_report_level"
        r["_label_confidence"] = conf

    fields = list(rows[0].keys())
    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    print("wrote %s (%d rows)\n" % (os.path.basename(OUT), len(rows)))
    counts = collections.Counter(r["VERDICT"] for r in rows)
    bad = sum(v for k, v in counts.items() if k.startswith(("NOT_", "TRUNCATED",
                                                           "DUP_", "WRONG_")))
    for k, v in counts.most_common():
        print("  %-24s %4d  (%.1f%%)" % (k, v, 100.0 * v / len(rows)))
    print("\n  confirmed-defect rows      : %d / %d = %.1f%%"
          % (bad, len(rows), 100.0 * bad / len(rows)))
    print("  awaiting human judgement   : %d"
          % (counts["REVIEW"] + counts["REVIEW_EXPANSION"]))
    print("  presumed-good (unverified) : %d" % counts["OK_PRESUMED"])

    print("\n  NOT_VICTIM_ROLE by report class:")
    rc_counts = collections.Counter(r["_report_class"] for r in rows
                                    if r["VERDICT"] == "NOT_VICTIM_ROLE")
    for k, v in rc_counts.most_common():
        print("    %-20s %3d" % (k, v))

    print("\n  label confidence:")
    for k, v in collections.Counter(r["_label_confidence"]
                                    for r in rows).most_common():
        print("    %-26s %4d" % (k, v))

    if "--audit" in sys.argv:
        # Every report-level suppression is auditable: a bad pattern here silently
        # discards real victims, so the titles it matched must be readable.
        print("\n########## AUDIT: titles matched by each report-class pattern ##########")
        for rc in ("influence_op", "hacktivist_claim", "phishing_infra",
                   "vendor_patch", "geopolitical"):
            titles = sorted({r["src_title"] for r in rows
                             if r["_report_class"] == rc})
            print("\n===== %s : %d reports =====" % (rc, len(titles)))
            for t in titles:
                names = [r["name"] for r in rows if r["src_title"] == t]
                print("  - %s" % t[:100])
                print("      -> %s" % "; ".join(names)[:150])

    if "--report" in sys.argv:
        for tag in ("REVIEW", "REVIEW_EXPANSION"):
            print("\n===== %s =====" % tag)
            for r in [x for x in rows if x["VERDICT"] == tag]:
                print("  %-40s | %s" % (r["name"][:40], r["src_title"][:70]))


if __name__ == "__main__":
    main()
