"""Thread-safe metrics, including the per-category outcome matrix.

link_rate = (existing + created) / (detected - generic - invalid
                                   - ungrounded - dup_suppressed)

Deliberate refusals are excluded from the denominator, because refusing a
name the guards rejected is correct behaviour, not a missed link. The
earlier single blended 'resolution_rate' mixed linkable categories with
never-linked ones and was misleading in both directions; it is retained
only for continuity."""
import threading
import time

# ---------------------------------------------------------------------------
# MetricsTracker (thread-safe counters + automated quality feedback)
# ---------------------------------------------------------------------------

class MetricsTracker:
    """Thread-safe counters for enrichment observability.

    Automated quality feedback: `names_suggested` counts entities Gemini
    named (actors, malware, techniques, sectors, countries); `names_resolved`
    counts how many actually became relationships in OpenCTI. The ratio is a
    proxy for enrichment quality that needs no human labelling — a run where
    Gemini names many entities that don't resolve indicates hallucination.
    """

    # Per-category outcome buckets. This is the honest, decomposed replacement
    # for the single blended resolution_rate: for each category we track how
    # many names Gemini detected and what happened to each one.
    _CATEGORIES = ("actor", "malware", "tool", "victim", "technique", "cve", "sector", "country")
    # 'dup_suppressed' = a novel name already claimed by another category in the
    # same enrichment, so this category deliberately did not also create it
    # (see _claim_novel). Like generic/invalid/ungrounded it is a correct
    # refusal, not a miss, so it is excluded from the link-rate denominator.
    _OUTCOMES = ("existing", "created", "would_create", "none", "generic", "invalid",
                 "ungrounded", "dup_suppressed")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.enrichments_total: int = 0
        self.enrichment_errors_total: int = 0
        self.reenrichments_total: int = 0
        self.names_suggested: int = 0
        self.names_resolved: int = 0
        self.by_category: dict = {
            cat: {outcome: 0 for outcome in self._OUTCOMES}
            for cat in self._CATEGORIES
        }
        self._start_time: float = time.monotonic()

    def record_category(self, category: str, outcome: str) -> None:
        """Record the outcome of a single detected name in a given category.

        category ∈ _CATEGORIES, outcome ∈ _OUTCOMES. Unknown values are ignored
        defensively so a typo never crashes an enrichment.
        """
        with self._lock:
            bucket = self.by_category.get(category)
            if bucket is not None and outcome in bucket:
                bucket[outcome] += 1

    def increment_success(self) -> None:
        with self._lock:
            self.enrichments_total += 1

    def increment_error(self) -> None:
        with self._lock:
            self.enrichment_errors_total += 1

    def increment_reenrichment(self) -> None:
        with self._lock:
            self.reenrichments_total += 1

    def record_resolution(self, suggested: int, resolved: int) -> None:
        """Record how many suggested entities resolved to real OpenCTI objects."""
        with self._lock:
            self.names_suggested += suggested
            self.names_resolved += resolved

    def should_log_summary(self) -> bool:
        with self._lock:
            total = self.enrichments_total + self.enrichment_errors_total
            return total > 0 and total % 100 == 0

    def summary_dict(self) -> dict:
        with self._lock:
            resolution_rate = (
                round(self.names_resolved / self.names_suggested, 3)
                if self.names_suggested > 0
                else None
            )
            # Per-category summary: detected total + link rate (existing+created
            # over detected). Deliberately-rejected outcomes (generic/junk,
            # malformed ids, and ungrounded names) are excluded from the
            # denominator: refusing them is correct behaviour, not a miss.
            category_summary = {}
            for cat, bucket in self.by_category.items():
                detected = sum(bucket.values())
                if detected == 0:
                    continue
                linkable = (
                    detected - bucket["generic"] - bucket["invalid"]
                    - bucket["ungrounded"] - bucket["dup_suppressed"]
                )
                linked = bucket["existing"] + bucket["created"]
                category_summary[cat] = {
                    **bucket,
                    "detected": detected,
                    "link_rate": round(linked / linkable, 3) if linkable > 0 else None,
                }
            return {
                "enrichments_total": self.enrichments_total,
                "enrichment_errors_total": self.enrichment_errors_total,
                "reenrichments_total": self.reenrichments_total,
                "names_suggested": self.names_suggested,
                "names_resolved": self.names_resolved,
                "resolution_rate": resolution_rate,
                "by_category": category_summary,
                "elapsed_seconds": round(time.monotonic() - self._start_time, 1),
            }

