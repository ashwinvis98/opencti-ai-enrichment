"""The connector itself: configuration, the enrichment pipeline, and the
per-entity decision funnel.

Built for OpenCTI with Google Gemini as the analysis model. The model call
is isolated in llm.py; everything else in this package is deterministic and
model-agnostic. Only Gemini has been run against a live platform."""
import hashlib
import json
import logging
import os
import re
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from pycti import OpenCTIConnectorHelper

from .llm import genai, genai_errors, genai_types
from .metrics import MetricsTracker
from .prompts import (SYSTEM_PREAMBLE, REPORT_PROMPT, INTRUSION_SET_PROMPT,
                      THREAT_ACTOR_PROMPT, MALWARE_PROMPT, CAMPAIGN_PROMPT,
                      VULNERABILITY_PROMPT, CRITIC_PROMPT)

# Re-exported wholesale so the package has one obvious entry point and so a
# reader (or a test) can reach any predicate from here.
from .names import *          # noqa: F401,F403
from .orgs import *           # noqa: F401,F403
from .grounding import *      # noqa: F401,F403
from .guards import *         # noqa: F401,F403
from .relations import *      # noqa: F401,F403
from .fetch import *          # noqa: F401,F403
from .vocab import *          # noqa: F401,F403
from .names import _norm_name, _dedup_key, _base_key, _LEET_MAP
from .orgs import (_org_key, _org_acronym, _org_acronyms, _org_sig_tokens,
                   _looks_like_domain, _is_acronym_form)
from .grounding import _grounding_haystack, _acronym_of
from .guards import _GENERIC_MARKERS, _JUNK_EXACT, _NAME_GAP
from .relations import _REL_MATRIX, _MITRE_RE
from .fetch import _SafeRedirectHandler, _FETCHABLE_CONTENT_TYPES


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    """Read a bounded integer env var, falling back to default when unusable."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except (ValueError, TypeError):
        logging.warning("%s='%s' invalid (expected %d-%d). Using %d.", name, raw, lo, hi, default)
        return default

# Marker embedded in the AI Summary note to record the content hash the
# enrichment was based on. Used to detect when re-enrichment is needed.
HASH_MARKER_RE = re.compile(r"\[ai-enrichment-hash:([0-9a-f]{16})\]")

# ---------------------------------------------------------------------------
# AIEnrichmentConnector
# ---------------------------------------------------------------------------

class AIEnrichmentConnector:
    """OpenCTI INTERNAL_ENRICHMENT connector backed by Google Gemini."""

    # Fields whose list values count toward the "suggested entities" total
    # for automated resolution-rate quality tracking.
    _RESOLVABLE_FIELDS = (
        "threat_actors",
        "associated_threat_actors",
        "malware_families",
        "attack_techniques",
        "cves",
        "targeted_sectors",
        "targeted_countries",
    )

    # Per-category creation overrides. Each accepts the same tri-state values as
    # AI_CREATE_STUBS (off | dry-run | on); unset means "inherit the global".
    #
    # Sectors, Attack-Patterns and CVEs are absent on purpose — always
    # lookup-only. CVE creation was removed after observing that proposed novel
    # CVE identifiers regularly do not exist at NVD *or* CVE.org, and that some
    # arrive verbatim in the source feed's own report title — so the groundedness
    # gate passes them and cannot help. NVD owns Vulnerabilities.
    # See OBSERVATIONS.md.
    _CREATE_ENV = {
        "actor": "AI_CREATE_ACTORS",
        "malware": "AI_CREATE_MALWARE",
        "tool": "AI_CREATE_TOOLS",
        "victim": "AI_CREATE_VICTIMS",
    }

    @staticmethod
    def _parse_create_mode(raw: str) -> str:
        """Normalise a tri-state creation setting to 'off' | 'dry-run' | 'on'."""
        value = (raw or "").strip().lower()
        if value in ("dry-run", "dryrun", "dry_run", "dry"):
            return "dry-run"
        if value in ("true", "1", "yes", "on"):
            return "on"
        return "off"

    def _may_create(self, category: str) -> bool:
        """True when this category is allowed to create entities live."""
        if self._read_only:
            return False
        return self._create_modes.get(category, self._create_mode) == "on"

    def _may_dryrun(self, category: str) -> bool:
        """True when this category should log (but not perform) creations."""
        return self._create_modes.get(category, self._create_mode) == "dry-run"

    def _creation_grounded(self, name, category: str) -> bool:
        """Gate creation on evidence: is `name` supported by the source text?

        Records an 'ungrounded' outcome and returns False when the check fails,
        so a read-only/dry-run run reports exactly how many creations were
        suppressed for lack of evidence.
        """
        if not self._require_grounding:
            return True
        if not self._src_text_norm:
            return True  # no source text captured; do not penalise
        if is_grounded(name, self._src_text_norm):
            return True
        self._note_cat(category, "ungrounded")
        self.helper.log_info(
            f"[GROUNDING] refusing to create {category} '{str(name).strip()}' — "
            "not supported by the source text"
        )
        return False

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def __init__(self) -> None:  # noqa: C901
        # --- Required: GEMINI_API_KEY ---
        gemini_api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if not gemini_api_key:
            logging.critical("FATAL: GEMINI_API_KEY environment variable is absent or empty. Exiting.")
            sys.exit(1)

        # --- Required: OPENCTI_TOKEN ---
        opencti_token = os.environ.get("OPENCTI_TOKEN", "").strip()
        if not opencti_token:
            logging.critical("FATAL: OPENCTI_TOKEN environment variable is absent or empty. Exiting.")
            sys.exit(1)

        # --- Required: CONNECTOR_ID ---
        connector_id = os.environ.get("CONNECTOR_ID", "").strip()
        if not connector_id:
            logging.critical("FATAL: CONNECTOR_ID environment variable is absent or empty. Exiting.")
            sys.exit(1)

        # --- Required (non-empty): AI_IDEMPOTENCY_LABEL ---
        idempotency_label = os.environ.get("AI_IDEMPOTENCY_LABEL", "ai-enriched").strip()
        if not idempotency_label:
            logging.critical(
                "FATAL: AI_IDEMPOTENCY_LABEL resolved to an empty or whitespace-only string. Exiting."
            )
            sys.exit(1)
        self.idempotency_label = idempotency_label

        # --- Optional: AI_CONTENT_LIMIT ---
        content_limit_raw = os.environ.get("AI_CONTENT_LIMIT", "")
        self.content_limit: int = 8000
        if content_limit_raw:
            try:
                parsed_limit = int(content_limit_raw)
                if parsed_limit < 1 or parsed_limit > 1_000_000:
                    raise ValueError("out of range")
                self.content_limit = parsed_limit
            except (ValueError, TypeError):
                logging.warning(
                    "AI_CONTENT_LIMIT='%s' is invalid (must be integer 1-1000000). Defaulting to 8000.",
                    content_limit_raw,
                )

        # --- Optional: CONNECTOR_AUTO ---
        auto_raw = os.environ.get("CONNECTOR_AUTO", "true").strip().lower()
        if auto_raw == "true":
            connector_auto = True
        elif auto_raw == "false":
            connector_auto = False
        else:
            logging.warning(
                "CONNECTOR_AUTO='%s' is not 'true' or 'false'. Defaulting to True.",
                os.environ.get("CONNECTOR_AUTO", ""),
            )
            connector_auto = True

        # --- Optional: CONNECTOR_NAME ---
        connector_name = os.environ.get("CONNECTOR_NAME", "").strip() or "AI Enrichment (Gemini)"

        # --- Optional: GEMINI_MODEL (dynamic routing) ---
        self._model_high_name = os.environ.get("GEMINI_MODEL_HIGH", "").strip() or \
            os.environ.get("GEMINI_MODEL", "").strip() or "gemini-3.6-flash"
        self._model_low_name = os.environ.get("GEMINI_MODEL_LOW", "").strip() or self._model_high_name
        routing_threshold_raw = os.environ.get("GEMINI_MODEL_ROUTING_THRESHOLD", "2000")
        try:
            self._routing_threshold = int(routing_threshold_raw)
            if self._routing_threshold < 1:
                raise ValueError("out of range")
        except (ValueError, TypeError):
            logging.warning(
                "GEMINI_MODEL_ROUTING_THRESHOLD='%s' is invalid. Defaulting to 2000.",
                routing_threshold_raw,
            )
            self._routing_threshold = 2000
        self._high_effort_types = {"report", "intrusion-set", "campaign"}

        # --- Optional: GEMINI_ENABLE_SEARCH (Google Search grounding mode) ---
        # Three modes:
        #   "auto"   (default) — decide per-entity: use search when it adds value
        #                        (external references present, or content is thin),
        #                        skip it for rich self-contained content.
        #   "always"/"true"    — always ground on Google Search.
        #   "never"/"false"    — never search; always use fast forced-JSON mode.
        # NOTE: the Gemini API does NOT allow search grounding together with forced
        # JSON mode, so when search is used we rely on prompt + fence-stripping.
        search_raw = os.environ.get("GEMINI_ENABLE_SEARCH", "auto").strip().lower()
        if search_raw in ("always", "true", "1", "yes"):
            self._search_mode = "always"
        elif search_raw in ("never", "false", "0", "no"):
            self._search_mode = "never"
        else:
            self._search_mode = "auto"
        # In auto mode, content shorter than this (chars) is considered "thin"
        # and triggers search so Gemini can draw on external/web knowledge.
        try:
            self._search_content_floor = max(0, int(os.environ.get("GEMINI_SEARCH_CONTENT_FLOOR", "500")))
        except (ValueError, TypeError):
            self._search_content_floor = 500

        # --- Optional: confidence decay + calibration ---
        decay_raw = os.environ.get("AI_CONFIDENCE_DECAY_ENABLED", "true").strip().lower()
        self._confidence_decay_enabled: bool = decay_raw in ("true", "1", "yes")
        calibration_raw = os.environ.get("AI_CONFIDENCE_CALIBRATION_OFFSET", "0").strip()
        try:
            self._calibration_offset = max(-50, min(50, int(calibration_raw)))
        except (ValueError, TypeError):
            logging.warning("AI_CONFIDENCE_CALIBRATION_OFFSET='%s' invalid. Defaulting to 0.", calibration_raw)
            self._calibration_offset = 0

        # --- Optional: label application controls ---
        labels_raw = os.environ.get("AI_APPLY_SUGGESTED_LABELS", "true").strip().lower()
        self._apply_suggested_labels: bool = labels_raw in ("true", "1", "yes")
        try:
            self._max_labels = max(0, min(25, int(os.environ.get("AI_MAX_LABELS", "10"))))
        except (ValueError, TypeError):
            self._max_labels = 10
        # --- Gated entity creation (tri-state) ---
        # AI_CREATE_STUBS controls whether entities Gemini names but which are NOT
        # already in the KB get created (behind the dedup/quality gate):
        #   "false"/off   → lookup-only; never create (default; current behaviour).
        #   "true"/on     → create the missing entity as a stub, tagged for review.
        #   "dry-run"     → do NOT create, but log exactly what WOULD be created,
        #                   so the write behaviour can be observed live before enabling.
        stubs_raw = os.environ.get("AI_CREATE_STUBS", "false").strip().lower()
        self._create_mode = self._parse_create_mode(stubs_raw)
        # Backward-compatible boolean: True only when creation is actually live.
        self._create_stubs: bool = self._create_mode == "on"
        self._create_dryrun: bool = self._create_mode == "dry-run"
        # STIX type of the entity currently being enriched (the relationship
        # SOURCE). Set at the top of each _enrich_* handler; used by
        # _link_or_contain to resolve a valid relationship type/direction.
        # None => resolver keeps the caller's preferred type (unit-test default).
        self._src_type: "str | None" = None
        # Name/title of the entity being enriched. Provenance from the same
        # source object, so it is legitimate evidence for canonicalising a
        # detected name (an acronym the title spells out) and for deciding
        # whether a name is described as a victim or as a leak-site operator.
        self._src_name: str = ""
        # Length of the entity's OWN content, before reference augmentation.
        # Set by _prepare(), consumed once by _call_gemini() for model routing.
        # See _resolve_model for why this must not be the augmented length.
        self._route_content_len: "int | None" = None
        # Novel names claimed during THIS enrichment, base_key -> category.
        # Cross-type dedup can only consult the KB, so a name that exists
        # nowhere yet can be proposed independently by two linkers; this is the
        # single ledger that arbitrates (see _claim_novel).
        self._novel_claims: dict = {}
        # True when the source material is ransomware/extortion reporting, in
        # which case a malware+actor pair for one brand is legitimate.
        self._ransomware_context: bool = False
        # Label applied to AI-created stub entities (and reserved from suggestions).
        self._review_label = os.environ.get("AI_REVIEW_LABEL", "ai-suggested").strip() or "ai-suggested"

        # --- Standalone-vulnerability auto-enrichment CVSS floor ---
        # Auto-summarising every NVD CVE is low graph value. When AI_MIN_CVSS > 0,
        # a standalone Vulnerability whose stored CVSS base score is below the floor
        # is skipped (0 = no gating; enrich everything as before).
        cvss_raw = os.environ.get("AI_MIN_CVSS", "0").strip()
        try:
            self._min_cvss = max(0.0, min(10.0, float(cvss_raw)))
        except (ValueError, TypeError):
            logging.warning("AI_MIN_CVSS='%s' invalid (must be 0-10). Defaulting to 0.", cvss_raw)
            self._min_cvss = 0.0

        # --- Alias write-back (self-improving dedup) ---
        # When enabled, aliases Gemini discovers for the entity being enriched are
        # added back to that entity, so future name matching improves over time.
        alias_raw = os.environ.get("AI_ALIAS_WRITEBACK", "false").strip().lower()
        self._alias_writeback: bool = alias_raw in ("true", "1", "yes", "on")

        # --- Critic / verification pass (PoC) ---
        # When enabled, a cheap second Gemini call (LOW model, no search) reviews
        # the extracted entities and flags mis-typed / generic / junk / victim-as-
        # actor items so they are dropped or reclassified before linking/creation.
        critic_raw = os.environ.get("AI_CRITIC_ENABLED", "false").strip().lower()
        self._critic_enabled: bool = critic_raw in ("true", "1", "yes", "on")

        # --- Durable audit log (survives container recreation) ---
        # Container logs die with the container, and metrics live in memory, so a
        # redeploy erases the evidence of how the connector behaved. When
        # AI_AUDIT_LOG points at a bind-mounted path, every log line is mirrored
        # there (rotating), and each metrics summary is appended as a JSON line to
        # ai_metrics.jsonl beside it — so performance can be analysed over time.
        self._audit_log_path = os.environ.get("AI_AUDIT_LOG", "").strip()
        self._audit_log_max_mb = _env_int("AI_AUDIT_LOG_MAX_MB", 64, 1, 4096)
        self._metrics_jsonl_path = ""
        if self._audit_log_path:
            self._metrics_jsonl_path = os.path.join(
                os.path.dirname(self._audit_log_path) or ".", "ai_metrics.jsonl"
            )
        # NOTE: the file handler is attached in _attach_audit_handler(), which must
        # run AFTER OpenCTIConnectorHelper is constructed — pycti reconfigures the
        # logging stack during init and would otherwise discard our handler
        # (symptom: audit file created but never written to).

        # --- External reference fetching (replaces Google Search grounding) ---
        # Previously the connector only pasted reference URLs into the prompt and
        # relied on Gemini's Search grounding to read them — which consumed a
        # separate, tightly-capped grounding quota. Fetching the article text
        # ourselves costs no Gemini quota, is deterministic (we control exactly
        # what the model sees), and works for open sources (RSS, blogs, vendor
        # write-ups). Auth-gated portals are detected and skipped.
        fetch_raw = os.environ.get("AI_FETCH_REFS", "true").strip().lower()
        self._fetch_refs: bool = fetch_raw in ("true", "1", "yes", "on")
        self._fetch_timeout = _env_int("AI_FETCH_TIMEOUT", 10, 1, 60)
        self._fetch_max_refs = _env_int("AI_FETCH_MAX_REFS", 3, 0, 10)
        self._fetch_max_chars = _env_int("AI_FETCH_MAX_CHARS_PER_REF", 4000, 200, 40000)
        self._fetch_max_bytes = _env_int("AI_FETCH_MAX_BYTES", 400_000, 10_000, 5_000_000)
        self._ref_cache: dict = {}

        # --- Groundedness requirement for entity CREATION ---
        # When enabled (default), the connector refuses to CREATE an entity whose
        # name is not traceable to the analysed source text. Deterministic, no
        # extra model call. Linking to already-existing entities is unaffected.
        ground_raw = os.environ.get("AI_REQUIRE_GROUNDING", "true").strip().lower()
        self._require_grounding: bool = ground_raw in ("true", "1", "yes", "on")
        # Normalised source text of the entity being enriched (set per enrichment).
        self._src_text_norm: str = ""

        # --- Per-category creation gating ---
        # AI_CREATE_STUBS is the global default (off | dry-run | on). Each entity
        # category can override it, so a category whose precision is proven can be
        # enabled WITHOUT enabling the noisier ones (e.g. create CVEs live while
        # actors/malware/tools stay in dry-run). Unset = inherit the global.
        # Sectors and Attack-Patterns are deliberately NOT here: they are always
        # lookup-only against their authoritative vocabularies.
        self._create_modes: dict = {}
        for _cat, _env in self._CREATE_ENV.items():
            _raw = os.environ.get(_env, "").strip().lower()
            self._create_modes[_cat] = self._parse_create_mode(_raw) if _raw else self._create_mode
        if self._create_mode != "off" or any(m != "off" for m in self._create_modes.values()):
            logging.info("Creation modes per category: %s", self._create_modes)

        # --- READ-ONLY / validation mode (top-level guardrail) ---
        # When enabled the connector runs the FULL analysis pipeline (detection,
        # critic, entity resolution, dedup, metrics) but writes NOTHING to the
        # knowledge graph: no notes, no labels, no structured fields, no
        # relationships, no entities. This exists so correctness can be proven
        # BEFORE the connector is ever allowed to modify the graph.
        # (Connector work/telemetry state is still reported — that is plumbing,
        # not knowledge.)
        ro_raw = os.environ.get("AI_READ_ONLY", "false").strip().lower()
        self._read_only: bool = ro_raw in ("true", "1", "yes", "on")
        if self._read_only:
            # Creation is forced off, but keep would-create accounting so a
            # read-only run still reports exactly what it *would* have created.
            self._create_stubs = False
            self._create_dryrun = True
            # Downgrade any live per-category setting to dry-run, otherwise an
            # "on" category would neither create nor be counted.
            self._create_modes = {
                cat: ("dry-run" if mode == "on" else mode)
                for cat, mode in self._create_modes.items()
            }

        # --- Proactive client-side rate limiting ---
        # Gemini enforces per-minute/per-day request quotas SERVER-side. Without
        # pacing, a busy feed pipeline triggers 429 storms where every rejected
        # call costs a long backoff sleep, collapsing effective throughput.
        # AI_MAX_RPM caps our own request rate so we stay under the quota instead
        # of repeatedly discovering it. 0 = no pacing (previous behaviour).
        try:
            self._max_rpm: int = max(0, int(os.environ.get("AI_MAX_RPM", "0").strip() or 0))
        except ValueError:
            self._max_rpm = 0
        self._min_call_interval: float = (60.0 / self._max_rpm) if self._max_rpm > 0 else 0.0
        self._last_call_at: float = 0.0
        self._rate_lock = threading.Lock()

        # --- Structured field enrichment (motivation, malware_types, cvss, ...) ---
        fields_raw = os.environ.get("AI_ENRICH_FIELDS", "true").strip().lower()
        self._enrich_fields: bool = fields_raw in ("true", "1", "yes", "on")

        # --- Sector controlled-vocabulary (anti-fragmentation) ---
        # Sectors are a curated, alias-rich vocabulary in the KB. By default the
        # connector is LOOKUP-ONLY for sectors: it links a detected sector to an
        # existing canonical sector by name OR alias, and NEVER creates a new
        # free-text sector. Free-text creation is what fragments the taxonomy in
        # the first place: an unchecked feed can multiply a couple of dozen
        # canonical sectors into several hundred near-duplicates.
        # Set AI_CREATE_SECTORS=true only if you deliberately want new ones.
        create_sec_raw = os.environ.get("AI_CREATE_SECTORS", "false").strip().lower()
        self._create_sectors: bool = create_sec_raw in ("true", "1", "yes", "on")

        # Labels the connector manages itself and must never re-apply as suggestions
        self._reserved_labels = {self.idempotency_label.lower(), self._review_label.lower()}

        # --- Configure Gemini SDK (new google-genai client) ---
        self._genai_client = genai.Client(api_key=gemini_api_key)

        # --- Configure OpenCTI helper ---
        opencti_url = os.environ.get("OPENCTI_URL", "http://localhost:8080").strip()
        config = {
            "opencti": {"url": opencti_url, "token": opencti_token},
            "connector": {
                "id": connector_id,
                "type": "INTERNAL_ENRICHMENT",
                "name": connector_name,
                "scope": "Report,Intrusion-Set,Threat-Actor-Group,Malware,Campaign,Vulnerability",
                "log_level": os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
                "auto": connector_auto,
            },
        }
        try:
            self.helper = OpenCTIConnectorHelper(config)
        except Exception as exc:  # noqa: BLE001
            logging.critical("FATAL: OpenCTIConnectorHelper initialisation failed: %s. Exiting.", exc)
            sys.exit(1)

        # Attach the durable audit handler now that pycti has finished configuring
        # logging (attaching earlier gets it discarded).
        self._attach_audit_handler()

        # --- Internal state ---
        self.metrics = MetricsTracker()
        self._shutdown_flag: bool = False
        self._active_enrichments: int = 0
        self._active_lock = threading.Lock()
        self._reenriched: bool = False          # set per-message in process_message
        self._pending_before: dict = {}         # snapshot passed from handler to _finalize
        # Provenance + loop guard: entities this process created, so the connector
        # never auto-enriches its own freshly-created stubs (feedback-loop guard).
        self._self_created_ids: set = set()
        self._author_id: "str | None" = None
        self._author_lookup_done: bool = False

    # ------------------------------------------------------------------
    # Model routing
    # ------------------------------------------------------------------

    def _resolve_model(self, entity_type: str, content_length: int) -> str:
        """Select the Gemini model name based on entity type and content length.

        `content_length` MUST be the length of the entity's own description, not
        the augmented prompt. Getting this wrong is a real cost bug: with a
        routing threshold of a couple of thousand characters and several
        thousand more appended by `_augment_with_refs`, a single retrieved
        article is enough to push a routine CVE enrichment over the threshold.
        Whether a reference happened to be fetched then decides the model tier,
        which is plumbing rather than a content-complexity signal.

        Vulnerability is deliberately absent from `_high_effort_types`; the whole
        point is that routine CVE summarisation runs on the cheap model.
        """
        if entity_type.lower() in self._high_effort_types:
            return self._model_high_name
        if content_length > self._routing_threshold:
            return self._model_high_name
        return self._model_low_name

    # ------------------------------------------------------------------
    # External references + content hashing
    # ------------------------------------------------------------------

    def _extract_external_refs(self, entity: dict) -> list:
        """Return a list of external reference URLs (and source names) on the entity."""
        refs = []
        for ref in entity.get("externalReferences", []) or []:
            if not isinstance(ref, dict):
                continue
            url = (ref.get("url") or "").strip()
            source = (ref.get("source_name") or "").strip()
            if url:
                refs.append(f"{source}: {url}" if source else url)
            elif source:
                refs.append(source)
        return refs

    def _augment_with_refs(self, content: str, entity: dict) -> str:
        """Append external references, FETCHING their text when possible.

        Listing bare URLs only helps if the model can open them, which required
        Google Search grounding and its scarce quota. We now retrieve the article
        text ourselves and inline it, so enrichment reaches full depth on open
        sources without consuming any grounding quota. Auth-gated portals are
        skipped (they would only return a login page).
        """
        refs = self._extract_external_refs(entity)
        if not refs:
            return content
        ref_block = "\n\nExternal references (investigate these sources):\n" + "\n".join(
            f"- {r}" for r in refs
        )
        fetched = self._fetch_reference_bodies(refs) if self._fetch_refs else []
        if fetched:
            ref_block += "\n\n--- Retrieved source content ---\n" + "\n\n".join(fetched)
        return content + ref_block

    @staticmethod
    def _ref_url(ref: str) -> str:
        """Extract the URL from a '<source>: <url>' reference entry."""
        m = re.search(r"https?://\S+", ref or "")
        return m.group(0).rstrip(").,;'\"") if m else ""

    def _fetch_reference_bodies(self, refs: list) -> list:
        """Fetch up to _fetch_max_refs reference bodies, newest-first, as text blocks."""
        blocks, used = [], 0
        for ref in refs:
            if used >= self._fetch_max_refs:
                break
            url = self._ref_url(ref)
            if not url:
                continue
            if url in self._ref_cache:
                text = self._ref_cache[url]
            elif is_gated_ref(url):
                self.helper.log_debug(f"[REF-FETCH] skipping auth-gated source: {url}")
                self._ref_cache[url] = None
                continue
            else:
                text = fetch_reference_text(url, self._fetch_timeout, self._fetch_max_bytes)
                # Bound the cache so a long-running connector cannot grow unbounded.
                if len(self._ref_cache) < 500:
                    self._ref_cache[url] = text
                if text:
                    self.helper.log_info(f"[REF-FETCH] retrieved {len(text)} chars from {url}")
                else:
                    self.helper.log_debug(f"[REF-FETCH] no usable text from {url}")
            if not text:
                continue
            blocks.append(f"[Source: {url}]\n{text[: self._fetch_max_chars]}")
            used += 1
        return blocks

    def _compute_entity_hash(self, entity: dict) -> str:
        """Compute a stable short hash of the entity's enrichment-relevant content.

        Includes description, name, and external reference URLs so that any change
        to the source material (new context, added references) triggers re-enrichment.
        """
        parts = [
            entity.get("description") or "",
            entity.get("name") or "",
            "|".join(self._extract_external_refs(entity)),
        ]
        joined = "\x1e".join(parts)
        return hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _list_ai_summary_notes(self, entity_id: str) -> list:
        """List the entity's 'AI Summary' notes via the ENTITY side.

        The top-level note.list(objects=...) filter does not reliably return
        notes attached to an entity on this platform, so we read the entity and
        traverse its `notes` relationship instead. pycti flattens the GraphQL
        edges into a list and exposes the abstract as 'attribute_abstract'.
        """
        r = self.helper.api.stix_domain_object.read(
            id=entity_id,
            customAttributes="notes { edges { node { id attribute_abstract content modified } } }",
        )
        notes = r.get("notes") if isinstance(r, dict) else None
        if isinstance(notes, dict):  # raw edges form
            notes = [e.get("node", {}) for e in notes.get("edges", [])]
        if not isinstance(notes, list):
            notes = []
        return [
            n for n in notes
            if (n.get("attribute_abstract") or n.get("abstract")) == "AI Summary"
        ]

    def _get_stored_hash(self, entity_id: str) -> "str | None":
        """Read the content hash recorded in the entity's AI Summary note, if any."""
        try:
            existing_notes = self._list_ai_summary_notes(entity_id)
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Failed to query notes for hash check on {entity_id}: {exc}")
            return None
        for note in existing_notes:
            match = HASH_MARKER_RE.search(note.get("content", "") or "")
            if match:
                return match.group(1)
        return None

    # ------------------------------------------------------------------
    # Gemini interaction
    # ------------------------------------------------------------------

    def _strip_fences(self, text: str) -> "str | None":
        """Remove markdown code fences from Gemini response text.

        Needed because when Google Search grounding is enabled we cannot use
        forced JSON mode, so Gemini may wrap JSON in fences.
        Returns None if an opening fence is found but no closing fence.
        """
        stripped = text.strip()
        json_open = re.search(r"```json\s*", stripped, re.IGNORECASE)
        if json_open:
            close = stripped.find("```", json_open.end())
            if close == -1:
                self.helper.log_error(
                    "Malformed Gemini response: opening ```json fence but no closing ```."
                )
                return None
            return stripped[json_open.end(): close].strip()
        generic_open = re.search(r"```\s*", stripped)
        if generic_open:
            close = stripped.find("```", generic_open.end())
            if close == -1:
                self.helper.log_error(
                    "Malformed Gemini response: opening ``` fence but no closing ```."
                )
                return None
            return stripped[generic_open.end(): close].strip()
        return stripped

    def _resolve_search(self, entity: dict, content: str) -> bool:
        """Decide whether to use Google Search grounding for THIS entity.

        Modes:
          never  → always False
          always → always True
          auto   → True when search adds value:
                     - the entity has external reference URLs to investigate, OR
                     - the source content is "thin" (below the content floor), so
                       Gemini needs external/web knowledge to enrich meaningfully.
                   Otherwise False (rich self-contained content → fast JSON mode).
        """
        if self._search_mode == "never":
            return False
        if self._search_mode == "always":
            return True
        # auto
        if self._extract_external_refs(entity):
            return True
        base = entity.get("description") or entity.get("name") or ""
        if len(base) < self._search_content_floor:
            return True
        return False

    def _build_config(self, use_search: bool):
        """Build the GenerateContentConfig.

        use_search True  → Google Search tool, no JSON mode (API restriction).
        use_search False → forced JSON mode for guaranteed valid JSON.
        """
        if use_search:
            return genai_types.GenerateContentConfig(
                tools=[genai_types.Tool(google_search=genai_types.GoogleSearch())],
            )
        return genai_types.GenerateContentConfig(
            response_mime_type="application/json",
        )

    def _attach_audit_handler(self) -> None:
        """Mirror every log line to a durable, rotating file on a bind mount.

        Must be called AFTER the pycti helper is constructed, because pycti
        reconfigures logging during its own init and would drop a handler that was
        attached earlier. Also raises the root level to INFO when needed, otherwise
        the connector's INFO records never reach any handler.
        """
        if not self._audit_log_path:
            return
        try:
            os.makedirs(os.path.dirname(self._audit_log_path) or ".", exist_ok=True)
            handler = RotatingFileHandler(
                self._audit_log_path,
                maxBytes=self._audit_log_max_mb * 1024 * 1024,
                backupCount=3,
            )
            handler.setLevel(logging.INFO)
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            )
            root = logging.getLogger()
            root.addHandler(handler)
            if root.level == logging.NOTSET or root.level > logging.INFO:
                root.setLevel(logging.INFO)
            logging.info(
                "[AUDIT] durable audit log enabled: %s (rotate %dMB x3); metrics -> %s",
                self._audit_log_path, self._audit_log_max_mb, self._metrics_jsonl_path,
            )
        except Exception as exc:  # noqa: BLE001
            logging.warning("Could not enable audit log '%s': %s", self._audit_log_path, exc)
            self._audit_log_path = ""
            self._metrics_jsonl_path = ""

    def _persist_metrics(self) -> None:
        """Append the metrics snapshot as a JSON line to durable storage.

        In-memory counters reset when the container restarts, so without this a
        redeploy erases the performance history. One JSON line per snapshot lets
        us chart behaviour over days.
        """
        if not self._metrics_jsonl_path:
            return
        try:
            snapshot = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "read_only": self._read_only,
                "create_modes": self._create_modes,
                "search_mode": self._search_mode,
                **self.metrics.summary_dict(),
            }
            with open(self._metrics_jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(snapshot, default=str) + "\n")
        except Exception as exc:  # noqa: BLE001
            self.helper.log_debug(f"Could not persist metrics snapshot: {exc}")

    def _throttle(self) -> None:
        """Block until the configured requests-per-minute budget allows a call.

        Proactive pacing: cheaper than discovering the server-side quota via 429
        storms, each of which costs a multi-minute backoff. No-op when AI_MAX_RPM
        is 0/unset.
        """
        if self._min_call_interval <= 0:
            return
        with self._rate_lock:
            now = time.monotonic()
            wait = self._min_call_interval - (now - self._last_call_at)
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._last_call_at = now

    def _call_gemini(
        self, prompt_template: str, content: str, entity_type: str = "", entity: "dict | None" = None
    ) -> "dict | None":
        """Call Gemini with retry logic, fence stripping, and JSON parsing.

        Search grounding is decided per-entity via _resolve_search.
        """
        truncated_content = content[: self.content_limit]
        # Capture exactly the text the model was shown (plus the entity's own
        # title, which is provenance from the same source object) as the
        # groundedness reference for this enrichment. Entity CREATION is later
        # checked against it so we never mint something untraceable.
        self._src_text_norm = _grounding_haystack(
            f"{truncated_content} {(entity or {}).get('name', '') or ''}"
        )
        # Per-enrichment context, reset here because every handler funnels
        # through this method exactly once per entity.
        self._src_name = str((entity or {}).get("name", "") or "")
        self._novel_claims = {}
        self._ransomware_context = any(
            marker in self._src_text_norm
            for marker in ("ransomware", "extortion", "leak site", "ransom note")
        )
        # Use replace (not str.format): the typed prompts contain literal JSON
        # braces ({"name": ...}) that str.format would misparse as fields.
        prompt = prompt_template.replace("{content}", truncated_content)

        use_search = self._resolve_search(entity or {}, truncated_content)
        self._last_used_search = use_search
        # Route on the entity's own content length, not the augmented prompt.
        # Consume-once: cleared immediately so a stale value from a previous
        # enrichment can never route this one, and any caller that bypasses
        # _prepare() falls back to the old behaviour rather than silently
        # inheriting someone else's length.
        route_len = self._route_content_len
        self._route_content_len = None
        if route_len is None:
            route_len = len(truncated_content)
        model_name = self._resolve_model(entity_type, route_len)
        self.helper.log_debug(
            f"Using model '{model_name}' for entity_type='{entity_type}' "
            f"(content_length={len(truncated_content)}, search={use_search}, mode={self._search_mode})"
        )

        config = self._build_config(use_search)
        last_error: "Exception | None" = None
        rate_limit_retries = 0
        transient_retries = 0

        for attempt in range(1, 4):
            try:
                self._throttle()
                response = self._genai_client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config,
                )
                raw_text = (response.text or "").strip()
            except genai_errors.APIError as exc:
                # google-genai raises APIError subclasses (ClientError 4xx,
                # ServerError 5xx). code 429 = rate limit; 5xx/None = transient;
                # other 4xx (400/401/403) = non-retryable.
                code = getattr(exc, "code", None)
                if code == 429:
                    rate_limit_retries += 1
                    if rate_limit_retries > 3:
                        last_error = exc
                        break
                    wait = 60 * rate_limit_retries
                    self.helper.log_warning(
                        f"Gemini rate limited (429, attempt {attempt}) — waiting {wait}s: {exc}"
                    )
                    time.sleep(wait)
                    continue
                if code is None or code >= 500:
                    transient_retries += 1
                    if transient_retries > 3:
                        last_error = exc
                        break
                    wait = 5 * transient_retries
                    self.helper.log_warning(
                        f"Gemini server error ({code}, attempt {attempt}) — waiting {wait}s: {exc}"
                    )
                    time.sleep(wait)
                    continue
                # Non-retryable 4xx (bad request, auth, invalid key, etc.)
                self.helper.log_error(f"Gemini non-retryable API error ({code}): {exc}")
                return None
            except (ConnectionError, TimeoutError) as exc:
                transient_retries += 1
                if transient_retries > 3:
                    last_error = exc
                    break
                wait = 5 * transient_retries
                self.helper.log_warning(
                    f"Gemini network error (attempt {attempt}) — waiting {wait}s: {exc}"
                )
                time.sleep(wait)
                continue
            except Exception as exc:  # noqa: BLE001
                self.helper.log_error(f"Gemini non-retryable error: {exc}")
                return None

            stripped = self._strip_fences(raw_text)
            if stripped is None:
                self.helper.log_error(
                    f"Gemini response failed fence stripping. Raw preview: {raw_text[:500]}"
                )
                return None

            try:
                return json.loads(stripped)
            except json.JSONDecodeError as exc:
                self.helper.log_error(
                    f"JSON decode failed: {exc}. Original response preview: {raw_text[:500]}"
                )
                return None

        self.helper.log_warning(f"Gemini call failed after all retries. Final error: {last_error}")
        return None

    # ------------------------------------------------------------------
    # Confidence parsing / calibration / decay
    # ------------------------------------------------------------------

    def _parse_confidence(self, result: dict) -> int:
        """Extract, clamp and calibrate confidence from a Gemini result dict."""
        raw = result.get("confidence")
        if raw is None or not isinstance(raw, (int, float)):
            self.helper.log_warning(
                f"Gemini response missing or non-numeric 'confidence' field (got {raw!r}). Defaulting to 50."
            )
            return 50
        clamped = max(0, min(100, int(raw)))
        calibrated = max(0, min(100, clamped + self._calibration_offset))
        return calibrated

    def _apply_age_decay(self, confidence: int, entity: dict) -> int:
        """Apply linear age-based decay to confidence (floor 50% over 2 years)."""
        date_str = entity.get("modified") or entity.get("created")
        if not date_str or not isinstance(date_str, str):
            return confidence
        try:
            entity_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if entity_date.tzinfo is None:
                entity_date = entity_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - entity_date).days
            decay_factor = max(0.5, 1.0 - (age_days / 730))
            return max(0, min(100, int(confidence * decay_factor)))
        except (ValueError, TypeError, OverflowError) as exc:
            self.helper.log_warning(
                f"Failed to parse entity date for confidence decay (date='{date_str}'): {exc}."
            )
            return confidence

    # ------------------------------------------------------------------
    # Re-enrichment decision + idempotency label
    # ------------------------------------------------------------------

    def _should_skip(self, entity: dict, current_hash: str) -> bool:
        """Return True if the entity was already enriched with identical content.

        Content-hash based: if the stored hash matches the current content hash,
        the source material is unchanged and we skip. If the hash differs (new
        context/references) or no hash is stored, we (re-)enrich.
        """
        stored = self._get_stored_hash(entity["id"])
        if stored is None:
            return False
        return stored == current_hash

    def _has_review_label(self, entity: dict) -> bool:
        """True if the entity carries the AI review label (i.e. it is an
        AI-created stub). Reads the common label shapes OpenCTI returns."""
        target = self._review_label.lower()
        for lbl in entity.get("objectLabel", []) or []:
            if isinstance(lbl, dict):
                value = lbl.get("value") or lbl.get("definition") or ""
            else:
                value = str(lbl)
            if value.strip().lower() == target:
                return True
        return False

    def _apply_idempotency_label(self, entity_id: str) -> bool:
        if self._read_only:
            self.helper.log_debug(f"[READ-ONLY] would label {entity_id} '{self.idempotency_label}'")
            return True
        try:
            self.helper.api.stix_domain_object.add_label(
                id=entity_id, label_name=self.idempotency_label
            )
            return True
        except Exception as exc:  # noqa: BLE001
            self.helper.log_error(f"Failed to apply idempotency label to entity {entity_id}: {exc}")
            return False

    # ------------------------------------------------------------------
    # Suggested labels
    # ------------------------------------------------------------------

    def _apply_labels(self, entity_id: str, labels: list) -> int:
        """Apply Gemini-suggested labels to the entity. Returns count applied."""
        if not self._apply_suggested_labels or not labels:
            return 0
        if self._read_only:
            eligible = [
                r.strip().lower() for r in labels[: self._max_labels]
                if isinstance(r, str) and r.strip() and r.strip().lower() not in self._reserved_labels
            ]
            self.helper.log_debug(f"[READ-ONLY] would apply {len(eligible)} label(s) to {entity_id}")
            return len(eligible)
        applied = 0
        for raw in labels[: self._max_labels]:
            if not isinstance(raw, str):
                continue
            name = raw.strip().lower()
            if not name or name in self._reserved_labels:
                continue
            try:
                self.helper.api.stix_domain_object.add_label(id=entity_id, label_name=name)
                applied += 1
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to apply suggested label '{name}' to {entity_id}: {exc}")
        return applied

    # ------------------------------------------------------------------
    # Note upsert (embeds content-hash marker)
    # ------------------------------------------------------------------

    def _add_or_update_note(
        self, entity_id: str, summary: str, confidence: int, content_hash: "str | None" = None
    ) -> None:
        """Create or update the 'AI Summary' Note, embedding the content hash marker."""
        if self._read_only:
            self.helper.log_debug(
                f"[READ-ONLY] would write AI Summary note on {entity_id} ({len(summary or '')} chars)"
            )
            return
        body = summary or ""
        if content_hash:
            body = f"{body}\n\n[ai-enrichment-hash:{content_hash}]"
        try:
            existing_notes = self._list_ai_summary_notes(entity_id)
        except Exception as exc:  # noqa: BLE001
            self.helper.log_error(f"Failed to query existing notes for entity {entity_id}: {exc}")
            return

        if not existing_notes:
            # pycti expects `objects` (list of entity ids) to LINK the note to the
            # entity. The prior `object_ids=` was silently ignored (**kwargs),
            # creating orphaned notes.
            self.helper.api.note.create(
                abstract="AI Summary",
                content=body,
                confidence=confidence,
                objects=[entity_id],
            )
        elif len(existing_notes) == 1:
            self.helper.api.note.update(
                id=existing_notes[0]["id"],
                input={"key": "content", "value": body},
            )
        else:
            self.helper.log_warning(
                f"Multiple AI Summary notes ({len(existing_notes)}) found for entity {entity_id}. "
                "Updating the most recently modified."
            )
            sorted_notes = sorted(existing_notes, key=lambda n: n.get("modified", ""), reverse=True)
            self.helper.api.note.update(
                id=sorted_notes[0]["id"],
                input={"key": "content", "value": body},
            )

    # ------------------------------------------------------------------
    # STIX writeback helpers
    # ------------------------------------------------------------------

    def _link_sectors(self, entity_id: str, sectors: list, confidence: int,
                      as_report_object: bool = False) -> int:
        created = 0
        for sector_name in sectors:
            if not sector_name or not str(sector_name).strip():
                self.helper.log_warning(f"Skipping blank/whitespace sector name for entity {entity_id}.")
                continue
            name = str(sector_name).strip()
            try:
                # Alias-aware resolve against the controlled Sector vocabulary:
                # any variant ("Cloud Services", "IT Services", ...) matches the
                # canonical sector via its aliases.
                results = self.helper.api.identity.list(search=name, first=30)
                candidates = [
                    r for r in results
                    if isinstance(r, dict) and r.get("entity_type") == "Sector"
                ] if isinstance(results, list) else []
                sector = self._match_by_name_or_alias(name, candidates)
                outcome = "existing"
                if not sector:
                    # Not in the controlled vocabulary. Do NOT create by default
                    # (prevents re-fragmenting the sector taxonomy).
                    # `not self._read_only` is required: AI_CREATE_SECTORS bypasses
                    # the per-category flags entirely, so without it read-only mode
                    # would still mint sectors.
                    if self._create_sectors and not self._read_only:
                        sector = self.helper.api.identity.create(type="Sector", name=name)
                        outcome = "created" if sector else "none"
                    else:
                        self._note_cat("sector", "none")
                        self.helper.log_debug(
                            f"Sector '{name}' not in controlled vocabulary — skipping (lookup-only)."
                        )
                        continue
                if sector:
                    if self._link_or_contain(entity_id, sector["id"], "targets",
                                             confidence, as_report_object,
                                             target_type="Sector"):
                        created += 1
                    self._note_cat("sector", outcome)
                else:
                    self._note_cat("sector", "none")
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to link sector '{name}' for entity {entity_id}: {exc}")
        return created

    def _link_countries(self, entity_id: str, country_codes: list, confidence: int,
                        as_report_object: bool = False) -> int:
        created = 0
        for code in country_codes:
            if not code or not re.fullmatch(r"[A-Za-z]{2}", code):
                self.helper.log_warning(
                    f"Skipping invalid country code '{code}' for entity {entity_id} "
                    "(must be exactly 2 ASCII alpha characters)."
                )
                continue
            try:
                location = self.helper.api.location.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "x_opencti_aliases", "values": [code.upper()]}],
                        "filterGroups": [],
                    }
                )
                if not location:
                    self._note_cat("country", "none")
                    self.helper.log_warning(f"No OpenCTI Location found for country code '{code}'. Skipping.")
                    continue
                if self._link_or_contain(entity_id, location["id"], "targets",
                                         confidence, as_report_object,
                                         target_type=location.get("entity_type") or "Country"):
                    created += 1
                self._note_cat("country", "existing")
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to link country '{code}' for entity {entity_id}: {exc}")
        return created

    @staticmethod
    def _match_by_name_or_alias(name: str, results: list) -> "dict | None":
        """Return the first result whose name or any alias matches `name`.

        Two passes, both conservative:
          1. Exact match on the whitespace/case-normalised name (no false
             positives from fulltext search).
          2. Dedup-key match (leetspeak + punctuation + trailing org suffix
             folded) so Cl0p==Clop and sh1ny==shiny resolve to the existing
             entity instead of creating a duplicate. Distinct names that differ
             by an inserted/removed letter (sandstorm vs standstorm) do NOT match.
        """
        target_norm = _norm_name(name)
        target_key = _dedup_key(name)

        def candidates_of(r):
            cands = [r.get("name", "")]
            cands += r.get("aliases") or []
            cands += r.get("x_opencti_aliases") or []
            return [c for c in cands if c]

        for r in results or []:
            if any(_norm_name(c) == target_norm for c in candidates_of(r)):
                return r
        if target_key:
            for r in results or []:
                if any(_dedup_key(c) == target_key for c in candidates_of(r)):
                    return r
        return None

    def _resolve_entity(self, readers, name: str) -> "dict | None":
        """Resolve an entity by name or alias (case-insensitive) across the given
        pycti readers, using fulltext search then a normalised exact match."""
        for reader in readers:
            try:
                results = reader.list(search=name, first=10)
            except Exception:  # noqa: BLE001
                results = None
            match = self._match_by_name_or_alias(name, results)
            if match:
                return match
        return None

    def _resolve_org(self, name: str) -> "dict | None":
        """Resolve a victim organisation, fuzzy-deduping name variants. Tries
        exact/alias/leet first, then an order-insensitive org-key (suffix/country/
        parenthetical/domain folded) so 'UK Office for Waterways' matches
        'Office for Waterways (UK)'. Only matches Organization identities."""
        try:
            results = self.helper.api.identity.list(search=name, first=30)
        except Exception:  # noqa: BLE001
            results = None
        orgs = [r for r in results if isinstance(r, dict) and r.get("entity_type") == "Organization"] \
            if isinstance(results, list) else []
        m = self._match_by_name_or_alias(name, orgs)
        if m:
            return m
        k = _org_key(name)
        if k:
            for e in orgs:
                cands = [e.get("name", "")] + (e.get("aliases") or []) + (e.get("x_opencti_aliases") or [])
                if any(_org_key(c) == k for c in cands if c):
                    return e
        # Acronym/expansion tier. Fulltext search for "NAWA" will not surface an
        # entity named "National Atmospheric and Water Agency" (and vice
        # versa), so search explicitly for the other form and compare.
        acronym = _org_acronym(name)
        if acronym:
            probe = acronym
        elif _is_acronym_form(name):
            probe = _norm_name(name)
        else:
            probe = ""
        if probe:
            try:
                extra = self.helper.api.identity.list(search=probe, first=30)
            except Exception:  # noqa: BLE001
                extra = None
            pool = [r for r in extra if isinstance(r, dict) and r.get("entity_type") == "Organization"] \
                if isinstance(extra, list) else []
            for e in pool + orgs:
                cands = [e.get("name", "")] + (e.get("aliases") or []) + (e.get("x_opencti_aliases") or [])
                if any(org_variants_match(name, c) for c in cands if c):
                    self.helper.log_info(
                        f"[ORG-DEDUP] '{str(name).strip()}' resolved to existing "
                        f"'{e.get('name')}' via acronym/expansion match"
                    )
                    return e
        return None

    def _resolve_by_base_key(self, readers, name: str) -> "dict | None":
        """Cross-type / suffix-tolerant resolve: matches on the base key (leet +
        malware-suffix folded), so 'Qilin Ransomware' resolves to an existing
        'Qilin' and an actor name resolves to its malware-family entity. Used only
        to AVOID creating duplicates — more aggressive than the primary matcher."""
        bk = _base_key(name)
        if not bk:
            return None
        for reader in readers:
            try:
                results = reader.list(search=name, first=10)
            except Exception:  # noqa: BLE001
                results = None
            if not isinstance(results, list):
                continue
            for e in results:
                if not isinstance(e, dict):
                    continue
                cands = [e.get("name", "")] + (e.get("aliases") or []) + (e.get("x_opencti_aliases") or [])
                if any(_base_key(c) == bk for c in cands if c):
                    return e
        return None

    def _note_cat(self, category: str, outcome: str) -> None:
        """Record a per-category outcome for the quality dashboard (best-effort)."""
        try:
            self.metrics.record_category(category, outcome)
        except Exception:  # noqa: BLE001
            pass

    def _claim_novel(self, category: str, name: str, type_hint: "str | None" = None) -> bool:
        """Arbitrate a novel name claimed by more than one category in one run.

        `_resolve_by_base_key` only consults the KB, so a name that exists
        nowhere yet can be proposed independently as both Malware and
        Intrusion-Set — which is how "Doommageddon" reached two would-create
        decisions. This is the ONE place that decides, instead of two linkers
        racing to the same conclusion.

        A malware + actor pair IS legitimate for ransomware brands (cf. Medusa:
        the malware family and the group that operates it), so the pair is
        allowed when the material is ransomware/extortion reporting — and is
        logged as a deliberate pair rather than happening silently. Every other
        duplicate claim is refused: the first category to claim the base name
        wins, which is deterministic because linker order is fixed.

        Returns True when this category may proceed to create/dry-run the name.
        """
        key = _base_key(name)
        if not key:
            return True
        prior = self._novel_claims.get(key)
        if prior is None:
            self._novel_claims[key] = category
            return True
        if prior == category:
            return False  # same category already claimed it in this enrichment
        ransomware_signal = self._ransomware_context or "ransom" in _norm_name(
            f"{name} {type_hint or ''}"
        )
        if {prior, category} == {"actor", "malware"} and ransomware_signal:
            self.helper.log_info(
                f"[CROSS-TYPE] '{str(name).strip()}' intentionally kept as both "
                f"{prior} and {category} — ransomware brand (family + operating group)"
            )
            return True
        self.helper.log_info(
            f"[CROSS-TYPE] refusing to also create {category} '{str(name).strip()}' — "
            f"already claimed as {prior} in this enrichment"
        )
        return False

    def _link_or_contain(self, entity_id: str, target_id: str, rel_type: str,
                         confidence: int, as_report_object: bool,
                         target_type: "str | None" = None) -> bool:
        """Create the graph edge for a detected entity.

        A Report is a STIX *container*: it does not have outgoing 'uses'/'targets'
        relationships. Instead detected entities are added to the report's object
        references (report contains X). For non-container SDOs (Intrusion-Set,
        Malware, Campaign, Threat-Actor) a normal typed relationship is created.

        The relationship type/direction is resolved against the source entity's
        type (self._src_type) and the target type so the edge is always
        STIX/OpenCTI-valid — e.g. enriching a Vulnerability produces
        'Attack-Pattern targets Vulnerability' rather than the invalid
        'Vulnerability uses Attack-Pattern'.
        """
        if self._read_only:
            if as_report_object:
                self.helper.log_debug(
                    f"[READ-ONLY] would add {target_id} to report {entity_id} object_refs"
                )
            else:
                rt, rev = resolve_rel(self._src_type, target_type, rel_type)
                direction = f"{target_id} -{rt}-> {entity_id}" if rev else f"{entity_id} -{rt}-> {target_id}"
                self.helper.log_debug(f"[READ-ONLY] would create relationship {direction}")
            return True
        if as_report_object:
            try:
                self.helper.api.report.add_stix_object_or_stix_relationship(
                    id=entity_id, stixObjectOrStixRelationshipId=target_id
                )
                return True
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(
                    f"Failed to add object {target_id} to report {entity_id}: {exc}"
                )
                return False
        rel_type, reverse = resolve_rel(self._src_type, target_type, rel_type)
        from_id, to_id = (target_id, entity_id) if reverse else (entity_id, target_id)
        rel = self.helper.api.stix_core_relationship.create(
            fromId=from_id, toId=to_id,
            relationship_type=rel_type, confidence=confidence,
        )
        return bool(rel)

    def _get_author_id(self) -> "str | None":
        """Lazily resolve (or create) the connector's author Identity so that
        AI-created/linked data is attributable and bulk-revertable. Cached; on any
        failure returns None and the write simply proceeds without an author."""
        if self._read_only:
            # Defence in depth: unreachable today because every caller sits behind
            # _may_create (false in read-only), but this method CREATES an
            # Identity, so it must never be one refactor away from firing.
            return None
        if self._author_lookup_done:
            return self._author_id
        self._author_lookup_done = True
        try:
            author = self.helper.api.identity.create(
                type="Organization",
                name="AI Enrichment (Gemini)",
                description="Automated enrichment author for the Gemini AI connector.",
            )
            self._author_id = author.get("id") if isinstance(author, dict) else None
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Could not resolve connector author identity: {exc}")
            self._author_id = None
        return self._author_id

    def _tag_created(self, stub: dict) -> None:
        """Apply the review label + record provenance for an AI-created entity."""
        if self._read_only:
            return
        if not isinstance(stub, dict) or not stub.get("id"):
            return
        self._self_created_ids.add(stub["id"])
        try:
            self.helper.api.stix_domain_object.add_label(
                id=stub["id"], label_name=self._review_label
            )
        except Exception:  # noqa: BLE001
            pass

    def _create_actor_stub(self, name: str) -> "dict | None":
        """Create a minimal Intrusion-Set stub for an AI-suggested actor, tagged
        with the review label. Only called when AI_CREATE_STUBS is enabled."""
        try:
            kwargs = {"name": name.strip(), "confidence": 30}
            author = self._get_author_id()
            if author:
                kwargs["createdBy"] = author
            stub = self.helper.api.intrusion_set.create(**kwargs)
            if stub:
                self._tag_created(stub)
            return stub
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Failed to create actor stub '{name}': {exc}")
            return None

    def _create_malware_stub(self, name: str, malware_type: "str | None" = None) -> "dict | None":
        """Create a minimal Malware stub for an AI-suggested family, tagged for review."""
        try:
            kwargs = {"name": name.strip(), "is_family": True, "confidence": 30}
            mtypes = normalize_malware_types([malware_type]) if malware_type else []
            if mtypes:
                kwargs["malware_types"] = mtypes
            author = self._get_author_id()
            if author:
                kwargs["createdBy"] = author
            stub = self.helper.api.malware.create(**kwargs)
            if stub:
                self._tag_created(stub)
            return stub
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Failed to create malware stub '{name}': {exc}")
            return None

    def _create_tool_stub(self, name: str, tool_type: "str | None" = None) -> "dict | None":
        """Create a minimal Tool stub for AI-suggested legitimate/dual-use software."""
        try:
            kwargs = {"name": name.strip(), "confidence": 30}
            ttypes = normalize_tool_types([tool_type]) if tool_type else []
            if ttypes:
                kwargs["tool_types"] = ttypes
            author = self._get_author_id()
            if author:
                kwargs["createdBy"] = author
            stub = self.helper.api.tool.create(**kwargs)
            if stub:
                self._tag_created(stub)
            return stub
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Failed to create tool stub '{name}': {exc}")
            return None

    def _create_victim_stub(self, name: str) -> "dict | None":
        """Create a minimal Identity (organization) stub for a targeted victim.

        The acronym is stored as an alias so a later report naming the same org
        by its short form resolves to THIS entity instead of creating a duplicate
        (self-improving dedup, durable across runs).
        """
        try:
            kwargs = {"type": "Organization", "name": name.strip()}
            # >= 3 chars only: a 2-letter acronym is too collision-prone to store.
            acronym = _org_acronym(name)
            if acronym and len(acronym) >= 3:
                kwargs["x_opencti_aliases"] = [acronym.upper()]
            author = self._get_author_id()
            if author:
                kwargs["createdBy"] = author
            stub = self.helper.api.identity.create(**kwargs)
            if stub:
                self._tag_created(stub)
            return stub
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Failed to create victim identity stub '{name}': {exc}")
            return None

    # NOTE: there is deliberately no _create_vuln_stub. Vulnerabilities are
    # lookup-only (see _link_vulnerabilities) because NVD/CVE.org owns them and
    # proposed novel CVE identifiers regularly turned out not to exist at either.
    # Leaving a creation helper in place would be an invitation to re-enable it.
    # See OBSERVATIONS.md.

    def _link_threat_actors(self, entity_id: str, names: list, confidence: int,
                            as_report_object: bool = False) -> int:
        created = 0
        for name in names:
            if not name or not name.strip():
                continue
            # Quality gate: never link/create generic descriptors.
            if is_generic_entity_name(name):
                self._note_cat("actor", "generic")
                self.helper.log_debug(f"Skipping generic actor descriptor '{name}'.")
                continue
            try:
                # 1) Intrusion-Set-first resolution (platform default for actors).
                actor = self._resolve_entity(
                    [self.helper.api.intrusion_set, self.helper.api.threat_actor_group], name
                )
                if not actor:
                    # Suffix/version-tolerant SAME-type match, which malware and
                    # tools already had but actors did not: "LockBit 5.0" must
                    # resolve to the existing "LockBit" rather than mint a
                    # versioned duplicate Intrusion-Set.
                    actor = self._resolve_by_base_key(
                        [self.helper.api.intrusion_set,
                         self.helper.api.threat_actor_group], name
                    )
                if actor:
                    if self._link_or_contain(entity_id, actor["id"], "related-to",
                                             confidence, as_report_object):
                        created += 1
                    self._note_cat("actor", "existing")
                    continue
                # 2) junk gate
                if is_junk_name(name):
                    self._note_cat("actor", "generic")
                    self.helper.log_debug(f"Skipping junk actor token '{name}'.")
                    continue
                # 2b) never MINT a criminal organisation, an operation/campaign
                # name, or a company as a threat actor. (Placed after resolution
                # so an entity that legitimately already exists still links.)
                if is_non_actor_name(name):
                    self._note_cat("actor", "generic")
                    self.helper.log_info(
                        f"Skipping non-actor name '{name}' "
                        "(criminal org / operation name / company)."
                    )
                    continue
                # 3) cross-type: exists as malware/tool? link to it (live AND dry-run).
                xt = self._resolve_by_base_key(
                    [self.helper.api.malware, self.helper.api.tool], name)
                if xt:
                    if self._link_or_contain(entity_id, xt["id"], "related-to",
                                             confidence, as_report_object):
                        created += 1
                    self._note_cat("actor", "existing")
                    continue
                # 4) genuinely novel -> create / dry-run-log / skip
                if not self._creation_grounded(name, "actor"):
                    continue
                # 4b) same-run cross-type arbitration (see _claim_novel)
                if not self._claim_novel("actor", name):
                    self._note_cat("actor", "dup_suppressed")
                    continue
                if self._may_create("actor"):
                    stub = self._create_actor_stub(name)
                    if stub and self._link_or_contain(entity_id, stub["id"], "related-to",
                                                      confidence, as_report_object):
                        created += 1
                    self._note_cat("actor", "created" if stub else "none")
                elif self._may_dryrun("actor"):
                    self.helper.log_info(f"[DRY-RUN] would create Intrusion-Set '{name.strip()}'")
                    self._note_cat("actor", "would_create")
                else:
                    self._note_cat("actor", "none")
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to link threat actor '{name}' for entity {entity_id}: {exc}")
        return created

    def _link_malware(self, entity_id: str, names: list, confidence: int,
                      as_report_object: bool = False) -> int:
        created = 0
        for item in names:
            # Accept bare name strings (legacy/tests) or {'name','type'} dicts.
            name = item.get("name") if isinstance(item, dict) else item
            type_hint = item.get("type") if isinstance(item, dict) else None
            if not name or not str(name).strip():
                continue
            if is_generic_entity_name(name):
                self._note_cat("malware", "generic")
                self.helper.log_debug(f"Skipping generic malware descriptor '{name}'.")
                continue
            try:
                # 1) exact/alias then suffix-tolerant same-type match
                malware = self._resolve_entity([self.helper.api.malware], name)
                if not malware:
                    malware = self._resolve_by_base_key([self.helper.api.malware], name)
                if malware:
                    if self._link_or_contain(entity_id, malware["id"], "uses",
                                             confidence, as_report_object,
                                             target_type="Malware"):
                        created += 1
                    self._note_cat("malware", "existing")
                    continue
                # 2) junk gate
                if is_junk_name(name):
                    self._note_cat("malware", "generic")
                    self.helper.log_debug(f"Skipping junk malware token '{name}'.")
                    continue
                # 3) cross-type: exists as an actor? link to it (live AND dry-run)
                #    instead of creating a duplicate malware.
                xt = self._resolve_by_base_key(
                    [self.helper.api.intrusion_set, self.helper.api.threat_actor_group], name)
                if xt:
                    # xt is actually an actor (cross-type dedup); resolver will
                    # reverse to a valid 'actor uses malware'-style edge.
                    if self._link_or_contain(entity_id, xt["id"], "uses",
                                             confidence, as_report_object,
                                             target_type=xt.get("entity_type")):
                        created += 1
                    self._note_cat("malware", "existing")
                    continue
                # 4) genuinely novel -> create / dry-run-log / skip
                if not self._creation_grounded(name, "malware"):
                    continue
                # 4b) same-run cross-type arbitration (see _claim_novel)
                if not self._claim_novel("malware", name, type_hint):
                    self._note_cat("malware", "dup_suppressed")
                    continue
                if self._may_create("malware"):
                    stub = self._create_malware_stub(name, malware_type=type_hint)
                    if stub and self._link_or_contain(entity_id, stub["id"], "uses",
                                                      confidence, as_report_object,
                                                      target_type="Malware"):
                        created += 1
                    self._note_cat("malware", "created" if stub else "none")
                elif self._may_dryrun("malware"):
                    self.helper.log_info(f"[DRY-RUN] would create Malware '{name.strip()}'")
                    self._note_cat("malware", "would_create")
                else:
                    self._note_cat("malware", "none")
                    self.helper.log_debug(f"Malware '{name}' not found in OpenCTI — skipping.")
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to link malware '{name}' for entity {entity_id}: {exc}")
        return created

    def _link_tools(self, entity_id: str, tool_items: list, confidence: int,
                    as_report_object: bool = False) -> int:
        """Link legitimate/dual-use software as Tool SDOs. tool_items is a list of
        {'name':..., 'type':...} dicts (or bare name strings)."""
        created = 0
        for item in tool_items or []:
            name = item.get("name") if isinstance(item, dict) else item
            type_hint = item.get("type") if isinstance(item, dict) else None
            if not name or not str(name).strip():
                continue
            if is_generic_entity_name(name):
                self._note_cat("tool", "generic")
                continue
            try:
                tool = self._resolve_entity([self.helper.api.tool], name)
                if not tool:
                    tool = self._resolve_by_base_key([self.helper.api.tool], name)
                if not tool:
                    # Cross-type: the same software may already exist as Malware
                    # (or as an actor's namesake). _link_malware and
                    # _link_threat_actors both did this; _link_tools did not, so
                    # a Tool duplicate was minted beside the existing entity.
                    # Found against a live KB: software such as Metasploit and
                    # UPX may be stored as Malware, yet was being reported as a
                    # Tool would-create. A meaningful share of tool
                    # would-creates came from this one gap.
                    tool = self._resolve_by_base_key(
                        [self.helper.api.malware,
                         self.helper.api.intrusion_set,
                         self.helper.api.threat_actor_group], name)
                    if tool:
                        if self._link_or_contain(
                            entity_id, tool["id"], "uses", confidence,
                            as_report_object, target_type=tool.get("entity_type")
                        ):
                            created += 1
                        self._note_cat("tool", "existing")
                        continue
                outcome = "none"
                if tool:
                    outcome = "existing"
                elif is_junk_name(name):
                    self._note_cat("tool", "generic")
                    continue
                elif not self._creation_grounded(name, "tool"):
                    continue
                elif not self._claim_novel("tool", name, type_hint):
                    self._note_cat("tool", "dup_suppressed")
                    continue
                elif self._may_create("tool"):
                    tool = self._create_tool_stub(name, tool_type=type_hint)
                    outcome = "created" if tool else "none"
                elif self._may_dryrun("tool"):
                    self.helper.log_info(f"[DRY-RUN] would create Tool '{str(name).strip()}'")
                    self._note_cat("tool", "would_create")
                    continue
                if tool:
                    if self._link_or_contain(entity_id, tool["id"], "uses",
                                             confidence, as_report_object,
                                             target_type="Tool"):
                        created += 1
                    self._note_cat("tool", outcome)
                else:
                    self._note_cat("tool", "none")
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to link tool '{name}' for entity {entity_id}: {exc}")
        return created

    def _link_victims(self, entity_id: str, names: list, confidence: int,
                      as_report_object: bool = False) -> int:
        """Link targeted victim organisations as Identity SDOs (victimology)."""
        created = 0
        # Same-run canonical cache. Two spellings of one org (e.g. "NAWA" and
        # "National Atmospheric and Water Agency") can both be novel in
        # the SAME result, so KB lookup cannot dedup them — the first one has not
        # been written yet. Fold them here before deciding to create.
        seen_orgs: list = []   # [(name, entity_id_or_None)]
        # The entity's own title is provenance from the same source object, so a
        # detection that is a partial rendering of it is the SAME organisation
        # ("Brightwell" vs "Brightwell Mess-Regeltechnik GmbH"). Seeding it here
        # means the existing fold path catches that without a second code path.
        src_title = self._src_name

        def cached(candidate):
            for prev_name, prev_id in seen_orgs:
                if (org_variants_match(prev_name, candidate)
                        or org_partial_match(candidate, prev_name)
                        or org_partial_match(prev_name, candidate)):
                    return prev_name, prev_id
            return None, None

        for name in names or []:
            if not name or not str(name).strip():
                continue
            if is_generic_entity_name(name) or is_junk_name(name):
                self._note_cat("victim", "generic")
                continue
            # An adversary brand, or a name the source shows OPERATING a leak
            # site, is an attacker — never a breached organisation. Observed
            # misfilings: "Business Data Leaks", "FulcrumSec", "Global Secret
            # Group" (all reclassified into victims by the critic pass).
            if is_adversary_brand_name(name) or is_leak_site_operator(
                name, src_title, self._src_text_norm
            ):
                self._note_cat("victim", "generic")
                self.helper.log_info(
                    f"[VICTIM-GUARD] '{str(name).strip()}' is a leak-site operator / "
                    "adversary brand — not a victim organisation"
                )
                continue
            try:
                # The source title may spell out an abbreviation the detection
                # used on its own ("HEPL" <- "… new victim: Harbour Enviro
                # (HEPL)"). Prefer the full name and keep the short form as an
                # alias, so one organisation does not land twice.
                canonical = canonical_name_from_title(name, src_title)
                if canonical:
                    self.helper.log_info(
                        f"[ORG-DEDUP] '{str(name).strip()}' expanded to "
                        f"'{canonical}' from the source title"
                    )
                    name = canonical
                else:
                    # Head-truncated form of the org named in the title
                    # ("Brightwell" <- "Brightwell Mess-Regeltechnik GmbH").
                    # Only a bare org-shaped title qualifies; a news headline is
                    # rejected by victim_name_from_title so it can never become
                    # an entity name.
                    title_org = victim_name_from_title(src_title)
                    if title_org and org_partial_match(name, title_org):
                        self.helper.log_info(
                            f"[ORG-DEDUP] '{str(name).strip()}' is a partial form of "
                            f"'{title_org}' from the source title — using the fuller name"
                        )
                        name = title_org
                prev_name, prev_id = cached(name)
                if prev_name is not None:
                    # Same org under a different spelling; link once, don't duplicate.
                    self.helper.log_info(
                        f"[ORG-DEDUP] '{str(name).strip()}' is a variant of "
                        f"'{prev_name}' — not creating a second entity"
                    )
                    if prev_id and self._link_or_contain(
                        entity_id, prev_id, "targets", confidence,
                        as_report_object, target_type="Organization"
                    ):
                        created += 1
                    continue
                victim = self._resolve_org(name)
                outcome = "none"
                if victim:
                    outcome = "existing"
                elif not self._creation_grounded(name, "victim"):
                    continue
                elif self._may_create("victim"):
                    victim = self._create_victim_stub(name)
                    outcome = "created" if victim else "none"
                elif self._may_dryrun("victim"):
                    self.helper.log_info(f"[DRY-RUN] would create Identity (victim) '{str(name).strip()}'")
                    self._note_cat("victim", "would_create")
                    # Record even in dry-run so variant spellings later in the
                    # same result are not double-counted as would-creates.
                    seen_orgs.append((str(name).strip(), None))
                    continue
                if victim:
                    seen_orgs.append((str(name).strip(), victim.get("id")))
                    if self._link_or_contain(entity_id, victim["id"], "targets",
                                             confidence, as_report_object,
                                             target_type="Organization"):
                        created += 1
                    self._note_cat("victim", outcome)
                else:
                    self._note_cat("victim", "none")
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to link victim '{name}' for entity {entity_id}: {exc}")
        return created

    @staticmethod
    def _extract_software(result: dict) -> tuple:
        """Split the typed 'software' field into (malware_items, tool_items).

        Each item is {'name','type'}. Classification: a known-legit software name
        or an item Gemini marks legitimate/kind=tool -> Tool; everything else ->
        Malware. Falls back to the legacy flat 'malware_families' list of strings.
        """
        malware, tools = [], []
        seen = set()

        def add(bucket, name, typ):
            key = _dedup_key(name)
            if key and key not in seen:
                seen.add(key)
                bucket.append({"name": name.strip(), "type": typ})

        def route(name, kind, legit, typ):
            # infra/platform or protocol/generic-utility noise -> drop entirely
            if is_infra_software(name) or is_tool_noise(name):
                return
            # defensive security products are the victim's, never the attacker's;
            # consumer AI/desktop apps are not adversary tooling either
            if is_security_product(name) or is_consumer_software_noise(name):
                return
            if is_miner(name):                      # cryptominers are malware
                add(malware, name, "resource-exploitation"); return
            if is_known_legit_software(name) or legit or kind == "tool":
                add(tools, name, typ)
            else:
                add(malware, name, typ)

        sw = result.get("software")
        if isinstance(sw, list):
            for it in sw:
                if isinstance(it, dict):
                    name = (it.get("name") or "").strip()
                    if not name:
                        continue
                    route(name, (it.get("kind") or "").strip().lower(),
                          bool(it.get("legitimate")), it.get("type"))
                elif isinstance(it, str) and it.strip():
                    route(it.strip(), "", False, None)
        legacy = result.get("malware_families")
        if isinstance(legacy, list):
            for it in legacy:
                if isinstance(it, str) and it.strip():
                    route(it.strip(), "malware", False, None)
        return malware, tools

    def _link_software(self, entity_id: str, result: dict, confidence: int,
                       as_report_object: bool = False) -> int:
        """Route the typed software field to Malware vs Tool linking."""
        malware_items, tool_items = self._extract_software(result)
        n = self._link_malware(entity_id, malware_items, confidence, as_report_object=as_report_object)
        n += self._link_tools(entity_id, tool_items, confidence, as_report_object=as_report_object)
        return n

    def _apply_entity_fields(self, reader, entity: dict, fields: dict) -> int:
        """Best-effort, NON-DESTRUCTIVE enrichment of structured fields on the
        entity being enriched: only sets a field that is currently empty, and
        silently skips fields the platform rejects (VALIDATION_ERROR)."""
        applied = 0
        for key, value in (fields or {}).items():
            if value in (None, "", [], {}):
                continue
            current = entity.get(key)
            if current not in (None, "", [], {}):
                continue  # never overwrite curated data
            if self._read_only:
                self.helper.log_debug(f"[READ-ONLY] would set field '{key}' on {entity.get('id')}")
                applied += 1
                continue
            try:
                reader.update_field(id=entity["id"], input={"key": key, "value": value})
                applied += 1
            except Exception as exc:  # noqa: BLE001
                self.helper.log_debug(f"Field '{key}' not applied to {entity.get('id')}: {exc}")
        return applied

    def _link_vulnerabilities(self, entity_id: str, cve_ids: list, confidence: int,
                              as_report_object: bool = False) -> int:
        """Link referenced CVEs — LOOKUP-ONLY.

        NVD/CVE.org is the authoritative source of Vulnerability entities (the
        platform imports them via its own connector). This connector never mints
        one, for the same reason it never mints an Attack-Pattern.

        Why, concretely: proposed novel CVE identifiers regularly turned out not
        to exist at NVD *or* CVE.org — 404 at both. `is_valid_cve` only checks
        the *shape* `CVE-dddd-dddd+`, so a well-formed fabrication passes it, and
        some arrived verbatim in the source feed's own report title, meaning the
        groundedness gate passes them too. Creating those would have been
        permanent graph debt in the service of someone else's typo.
        See OBSERVATIONS.md.

        Unknown CVEs are dry-run-logged (so the volume stays visible in metrics)
        or skipped. Direction is resolved by _link_or_contain.
        """
        created = 0
        for cve in cve_ids or []:
            if not cve or not str(cve).strip():
                continue
            cve_id = str(cve).strip().upper()
            if not is_valid_cve(cve_id):
                self._note_cat("cve", "invalid")
                self.helper.log_debug(f"Skipping malformed CVE id '{cve}'.")
                continue
            try:
                vuln = self._resolve_entity([self.helper.api.vulnerability], cve_id)
                if vuln:
                    if self._link_or_contain(entity_id, vuln["id"], "related-to",
                                             confidence, as_report_object):
                        created += 1
                    self._note_cat("cve", "existing")
                elif self._create_dryrun:
                    self.helper.log_info(
                        f"[DRY-RUN] would link CVE '{cve_id}' (not present in the KB)"
                    )
                    self._note_cat("cve", "would_create")
                else:
                    self._note_cat("cve", "none")
                    self.helper.log_debug(
                        f"CVE '{cve_id}' not in the KB — skipping (lookup-only; NVD owns "
                        "Vulnerabilities)."
                    )
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to link CVE '{cve_id}' for entity {entity_id}: {exc}")
        return created

    def _link_attack_patterns(self, entity_id: str, technique_ids: list, confidence: int,
                              as_report_object: bool = False) -> int:
        """Link MITRE ATT&CK techniques — LOOKUP-ONLY.

        The MITRE ATT&CK dataset is the authoritative source of Attack-Patterns
        (imported by the dedicated MITRE connector). This connector never mints
        Attack-Patterns: doing so produced hollow shells and junk ids (e.g.
        'T352', 'T367', or non-existent sub-techniques). We validate the id
        format, then link ONLY to an existing ATT&CK pattern; unknown techniques
        are dry-run-logged or skipped. Direction is resolved by _link_or_contain
        (e.g. a Vulnerability source yields 'Attack-Pattern targets Vulnerability').
        """
        created = 0
        for tid in technique_ids or []:
            if not tid or not str(tid).strip():
                continue
            tid = str(tid).strip().upper()
            if not is_valid_mitre_id(tid):
                self._note_cat("technique", "invalid")
                self.helper.log_debug(f"Skipping malformed technique id '{tid}'.")
                continue
            try:
                pattern = self.helper.api.attack_pattern.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "x_mitre_id", "values": [tid]}],
                        "filterGroups": [],
                    }
                )
                if pattern:
                    if self._link_or_contain(entity_id, pattern["id"], "uses",
                                             confidence, as_report_object,
                                             target_type="Attack-Pattern"):
                        created += 1
                    self._note_cat("technique", "existing")
                elif self._create_dryrun:
                    self.helper.log_info(
                        f"[DRY-RUN] would link technique '{tid}' (not present in ATT&CK KB)"
                    )
                    self._note_cat("technique", "would_create")
                else:
                    self._note_cat("technique", "none")
                    self.helper.log_debug(
                        f"Technique '{tid}' not in ATT&CK KB — skipping (lookup-only)."
                    )
            except Exception as exc:  # noqa: BLE001
                self.helper.log_warning(f"Failed to link attack pattern '{tid}' for entity {entity_id}: {exc}")
        return created

    def _update_score(self, entity_id: str, confidence: int) -> bool:
        """Update x_opencti_score (integer). Many SDO types (Report, Intrusion-Set,
        etc.) do not support x_opencti_score on this platform; those raise a
        VALIDATION_ERROR which we treat as 'not applicable' (debug, not error) so
        the logs stay clean. x_opencti_score IS valid on Indicators/Observables.
        READ-ONLY LEAK, fixed: this method had no `_read_only` guard, so while
        the connector reported "zero graph writes" it was in fact issuing a
        `stix_domain_object.update_field` mutation on every enrichment, observed
        overwriting a stored score on a Vulnerability. It went unnoticed because
        the read-only verification compared note, relationship and entity
        COUNTS, and a scalar field update on an existing entity changes none of
        those — the check was structurally blind to it. The lesson is in
        tests/: assert on the ABSENCE OF MUTATIONS, not the stability of counts.
        """
        if self._read_only:
            self.helper.log_debug(
                f"[READ-ONLY] would set x_opencti_score={int(confidence)} on {entity_id}"
            )
            return True
        try:
            self.helper.api.stix_domain_object.update_field(
                id=entity_id,
                input={"key": "x_opencti_score", "value": int(confidence)},
            )
            return True
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "incompatible attribute" in msg or "VALIDATION_ERROR" in msg:
                self.helper.log_debug(
                    f"Score not applicable for entity {entity_id} "
                    "(x_opencti_score unsupported on this entity type)."
                )
            else:
                self.helper.log_error(f"Failed to update score for entity {entity_id}: {exc}")
            return False

    # ------------------------------------------------------------------
    # Quality tracking helper
    # ------------------------------------------------------------------

    def _count_suggested(self, result: dict) -> int:
        """Count total resolvable entities Gemini named (for resolution-rate tracking)."""
        total = 0
        for field in self._RESOLVABLE_FIELDS:
            value = result.get(field)
            if isinstance(value, list):
                total += len([v for v in value if isinstance(v, str) and v.strip()])
        return total

    # ------------------------------------------------------------------
    # Brain audit logging + alias write-back
    # ------------------------------------------------------------------

    def _audit_detection(self, entity_type: str, entity_id: str, result: dict) -> None:
        """Log exactly what the brain detected, so detection quality is auditable
        in production independent of what linked. This is the raw signal."""
        def _names(field):
            v = result.get(field)
            return [x for x in v if isinstance(x, str) and x.strip()] if isinstance(v, list) else []

        malware_items, tool_items = self._extract_software(result)
        detected = {
            "actors": _names("threat_actors") or _names("associated_threat_actors"),
            "victims": _names("victims"),
            "malware": [m["name"] for m in malware_items],
            "tools": [t["name"] for t in tool_items],
            "techniques": _names("attack_techniques"),
            "cves": _names("cves"),
            "sectors": _names("targeted_sectors"),
            "countries": _names("targeted_countries"),
            "aliases": _names("aliases"),
        }
        self.helper.log_info(
            f"[AI-DETECTION] entity_type={entity_type} entity_id={entity_id} "
            f"confidence={result.get('confidence')} search={getattr(self, '_last_used_search', None)} "
            f"detected={json.dumps(detected, ensure_ascii=False)}"
        )

    def _vet_actor_to_victim(self, a2v: set, actor_names: list) -> set:
        """Filter the critic's actor -> victim moves down to the defensible ones.

        The critic is a single cheap model call with no evidence, while the
        primary extraction is prompted with explicit rules that victims are never
        actors. Measured in production, every observed reclassification was
        WRONG: "FulcrumSec", "Global Secret Group", "Business Data Leaks" and
        "Lego Resistance Front" were all correctly extracted as threat actors and
        then moved into `victims`, where they would have been created as victim
        organisations.

        So the burden of proof sits on the move, not on keeping the original
        classification. A move is honoured only with deterministic support:
          - the name is a known security vendor/product (the genuine case the
            critic exists to catch — a defender listed as an attacker), or
          - the source text actually describes the name as breached.
        And it is refused outright when the name is adversary self-branding, is
        shown operating a leak site, or already exists in the KB as an actor
        (authoritative data wins over a model's second opinion).
        """
        if not a2v:
            return a2v
        by_norm = {_norm_name(a): a for a in actor_names if isinstance(a, str)}
        kept = set()
        for n in a2v:
            raw = by_norm.get(n, n)
            if is_adversary_brand_name(raw):
                self.helper.log_info(
                    f"[CRITIC-GUARD] keeping '{raw}' as an actor — adversary brand name"
                )
                continue
            if is_leak_site_operator(raw, self._src_name, self._src_text_norm):
                self.helper.log_info(
                    f"[CRITIC-GUARD] keeping '{raw}' as an actor — the source shows it "
                    "operating a leak site / publishing victims"
                )
                continue
            if is_security_product(raw):
                kept.add(n)
                continue
            if has_victim_context(raw, self._src_name, self._src_text_norm):
                kept.add(n)
                continue
            try:
                existing_actor = self._resolve_entity(
                    [self.helper.api.intrusion_set, self.helper.api.threat_actor_group], raw
                )
            except Exception:  # noqa: BLE001
                existing_actor = None
            if existing_actor:
                self.helper.log_info(
                    f"[CRITIC-GUARD] keeping '{raw}' as an actor — it already exists in "
                    f"the knowledge base as {existing_actor.get('entity_type')}"
                )
                continue
            self.helper.log_info(
                f"[CRITIC-GUARD] keeping '{raw}' as an actor — no victim evidence in "
                "the source for the critic's reclassification"
            )
        return kept

    def _run_critic(self, result: dict, entity_type: str) -> None:
        """Second-pass verification: ask the LOW model to flag mis-typed / junk /
        victim-as-actor items, then rewrite `result` in place. Best-effort — any
        failure leaves the extraction untouched (never blocks enrichment)."""
        # Build the candidate list from whatever fields this result has.
        actors = [a for a in (result.get("threat_actors") or []) if isinstance(a, str) and a.strip()]
        assoc = [a for a in (result.get("associated_threat_actors") or []) if isinstance(a, str) and a.strip()]
        victims = [v for v in (result.get("victims") or []) if isinstance(v, str) and v.strip()]
        sw = result.get("software") if isinstance(result.get("software"), list) else []
        sw_named = []
        for it in sw:
            if isinstance(it, dict) and (it.get("name") or "").strip():
                sw_named.append({"name": it["name"], "kind": it.get("kind", "malware")})
            elif isinstance(it, str) and it.strip():
                sw_named.append({"name": it, "kind": "malware"})
        legacy_mw = [m for m in (result.get("malware_families") or []) if isinstance(m, str) and m.strip()]
        for m in legacy_mw:
            sw_named.append({"name": m, "kind": "malware"})

        if not (actors or assoc or victims or sw_named):
            return

        candidates = {
            "threat_actors": actors + assoc,
            "victims": victims,
            "software": sw_named,
        }
        try:
            self._throttle()
            resp = self._genai_client.models.generate_content(
                model=self._model_low_name,
                contents=CRITIC_PROMPT.replace("{content}", json.dumps(candidates, ensure_ascii=False)),
                config=genai_types.GenerateContentConfig(response_mime_type="application/json"),
            )
            verdict = json.loads(self._strip_fences(resp.text or "") or "{}")
        except Exception as exc:  # noqa: BLE001
            self.helper.log_debug(f"Critic pass skipped (error): {exc}")
            return
        if not isinstance(verdict, dict):
            return

        drop = {_norm_name(x) for x in verdict.get("drop", []) if isinstance(x, str)}
        a2v = {_norm_name(x) for x in verdict.get("actor_to_victim", []) if isinstance(x, str)}
        a2v = self._vet_actor_to_victim(a2v, actors + assoc)
        to_tool = {_dedup_key(x) for x in verdict.get("to_tool", []) if isinstance(x, str)}
        to_mal = {_dedup_key(x) for x in verdict.get("to_malware", []) if isinstance(x, str)}

        # threat_actors: drop noise, move victims out
        new_victims = list(victims)
        kept_actors = []
        for a in actors:
            n = _norm_name(a)
            if n in drop:
                continue
            if n in a2v:
                new_victims.append(a)
                continue
            kept_actors.append(a)
        if "threat_actors" in result:
            result["threat_actors"] = kept_actors
        if assoc:
            result["associated_threat_actors"] = [
                a for a in assoc if _norm_name(a) not in drop and _norm_name(a) not in a2v
            ]
        result["victims"] = [v for v in new_victims if _norm_name(v) not in drop]

        # software: drop noise, apply type corrections
        if isinstance(result.get("software"), list):
            fixed = []
            for it in result["software"]:
                nm = it.get("name", "") if isinstance(it, dict) else it
                if not nm or _norm_name(nm) in drop:
                    continue
                if isinstance(it, dict):
                    k = _dedup_key(nm)
                    if k in to_tool:
                        it["kind"] = "tool"; it["legitimate"] = True
                    elif k in to_mal:
                        it["kind"] = "malware"; it["legitimate"] = False
                fixed.append(it)
            result["software"] = fixed
        if isinstance(result.get("malware_families"), list):
            result["malware_families"] = [
                m for m in result["malware_families"] if _norm_name(m) not in drop
            ]

        self.helper.log_info(
            f"[AI-CRITIC] entity_type={entity_type} dropped={len(drop)} "
            f"actor_to_victim={len(a2v)} to_tool={len(to_tool)} to_malware={len(to_mal)}"
        )

    def _apply_aliases(self, reader, entity: dict, aliases: list) -> int:
        """Write newly-discovered aliases back to the entity being enriched, so
        future name matching improves (self-improving dedup). Conservative: only
        adds non-generic aliases not already present; gated by AI_ALIAS_WRITEBACK."""
        if self._read_only or not self._alias_writeback or not aliases:
            return 0
        existing = entity.get("aliases") or entity.get("x_opencti_aliases") or []
        existing_keys = {_dedup_key(a) for a in existing if a}
        entity_key = _dedup_key(entity.get("name", ""))
        additions = []
        for a in aliases:
            if not isinstance(a, str) or not a.strip() or is_generic_entity_name(a):
                continue
            key = _dedup_key(a)
            if not key or key == entity_key or key in existing_keys:
                continue
            existing_keys.add(key)
            additions.append(a.strip())
        if not additions:
            return 0
        try:
            reader.update_field(
                id=entity["id"],
                input={"key": "aliases", "value": list(existing) + additions},
            )
            self.helper.log_info(
                f"[ALIAS-WRITEBACK] added {len(additions)} alias(es) to {entity['id']}: {additions}"
            )
            return len(additions)
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Alias write-back failed for {entity['id']}: {exc}")
            return 0

    # ------------------------------------------------------------------
    # Snapshot and comparison log
    # ------------------------------------------------------------------

    def _snapshot_before(self, entity: dict) -> dict:
        score_before = entity.get("x_opencti_score")
        notes_count = 0
        for obj in entity.get("objects", []):
            if obj.get("entity_type") == "Note" and obj.get("abstract") == "AI Summary":
                notes_count += 1
        return {"score_before": score_before, "notes_count": notes_count}

    def _log_comparison(self, before, after, entity_type, entity_name, entity_id) -> None:
        score_before = before.get("score_before")
        score_after = after.get("score_after")
        notes_before = before.get("notes_count", 0)
        notes_after = after.get("notes_added", 0) + after.get("notes_updated", 0) + notes_before
        relationships_added = after.get("relationships_added", 0)
        gemini_confidence = after.get("gemini_confidence", 0)
        suggested = after.get("suggested", 0)
        resolution = round(relationships_added / suggested, 2) if suggested else "n/a"

        score_before_str = "null" if score_before is None else str(score_before)
        score_after_str = "null" if score_after is None else str(score_after)

        self.helper.log_info(
            f"[AI-ENRICHMENT] entity_type={entity_type} entity_id={entity_id} "
            f'entity_name="{entity_name}" notes_before={notes_before} notes_after={notes_after} '
            f"relationships_added={relationships_added} suggested={suggested} "
            f"resolution_rate={resolution} labels_added={after.get('labels_added', 0)} "
            f"score_before={score_before_str} score_after={score_after_str} "
            f"gemini_confidence={gemini_confidence} reenriched={after.get('reenriched', False)}"
        )

    # ------------------------------------------------------------------
    # Per-entity enrichment handlers
    # ------------------------------------------------------------------

    def _finalize(self, entity, entity_type_label, result, confidence, rel_count,
                  content_hash, reenriched, note_content=None) -> str:
        """Shared post-processing: labels, score, resolution tracking, comparison log."""
        entity_id = entity["id"]
        entity_name = entity.get("name", entity_id)

        labels_added = self._apply_labels(entity_id, result.get("suggested_labels", []))
        score_updated = self._update_score(entity_id, confidence)

        suggested = self._count_suggested(result)
        self.metrics.record_resolution(suggested, rel_count)
        if reenriched:
            self.metrics.increment_reenrichment()

        after = {
            "notes_added": 1,
            "notes_updated": 0,
            "relationships_added": rel_count,
            "score_after": confidence if score_updated else None,
            "gemini_confidence": confidence,
            "suggested": suggested,
            "labels_added": labels_added,
            "reenriched": reenriched,
        }
        self._log_comparison(
            self._pending_before, after, entity_type_label, entity_name, entity_id
        )
        return "Enriched"

    def _prepare(self, entity: dict, min_report: bool = False) -> "str | None":
        """Return the content string to send to Gemini, or None if too short.

        Also records the PRE-augmentation length for model routing. The returned
        string has reference article text appended, which is plumbing rather than
        a signal about how hard the entity is to analyse — see _resolve_model.
        """
        if min_report:
            description = entity.get("description") or ""
            content = description if len(description) >= 50 else entity.get("name", "")
        else:
            content = entity.get("description") or entity.get("name", "")
        if not content or len(content) < 10:
            self._route_content_len = None
            return None
        self._route_content_len = len(content)
        return self._augment_with_refs(content, entity)

    def _enrich_report(self, entity: dict, content_hash: "str | None" = None) -> str:
        content = self._prepare(entity, min_report=True)
        if content is None:
            return "Skipped: content too short"
        self._pending_before = self._snapshot_before(entity)
        result = self._call_gemini(REPORT_PROMPT, content, entity_type="report", entity=entity)
        if result is None:
            return "Skipped: Gemini error"
        confidence = self._parse_confidence(result)
        if self._confidence_decay_enabled:
            confidence = self._apply_age_decay(confidence, entity)
        entity_id = entity["id"]
        self._audit_detection("report", entity_id, result)
        self._src_type = "Report"
        if self._critic_enabled:
            self._run_critic(result, "report")
        rel = 0
        summary = result.get("summary", "")
        affected = coerce_names(result.get("affected_products"))
        if affected:
            summary = (summary + "\n\nAffected products: " + ", ".join(affected)).strip()
        self._add_or_update_note(entity_id, summary, confidence, content_hash)
        # A Report is a container: detected entities are added to its object refs
        # (report contains X), not linked via outgoing uses/targets relationships.
        rel += self._link_threat_actors(entity_id, result.get("threat_actors", []), confidence, as_report_object=True)
        rel += self._link_victims(entity_id, result.get("victims", []), confidence, as_report_object=True)
        rel += self._link_software(entity_id, result, confidence, as_report_object=True)
        rel += self._link_attack_patterns(entity_id, result.get("attack_techniques", []), confidence, as_report_object=True)
        rel += self._link_vulnerabilities(entity_id, result.get("cves", []), confidence, as_report_object=True)
        rel += self._link_sectors(entity_id, result.get("targeted_sectors", []), confidence, as_report_object=True)
        rel += self._link_countries(entity_id, result.get("targeted_countries", []), confidence, as_report_object=True)
        return self._finalize(entity, "Report", result, confidence, rel, content_hash,
                              reenriched=content_hash is not None and self._reenriched)

    def _enrich_intrusion_set(self, entity: dict, content_hash: "str | None" = None) -> str:
        content = self._prepare(entity)
        if content is None:
            return "Skipped: content too short"
        self._pending_before = self._snapshot_before(entity)
        result = self._call_gemini(INTRUSION_SET_PROMPT, content, entity_type="intrusion-set", entity=entity)
        if result is None:
            return "Skipped: Gemini error"
        confidence = self._parse_confidence(result)
        if self._confidence_decay_enabled:
            confidence = self._apply_age_decay(confidence, entity)
        entity_id = entity["id"]
        self._audit_detection("intrusion-set", entity_id, result)
        self._src_type = "Intrusion-Set"
        if self._critic_enabled:
            self._run_critic(result, "intrusion-set")
        rel = 0
        self._add_or_update_note(entity_id, result.get("summary", ""), confidence, content_hash)
        self._apply_aliases(self.helper.api.intrusion_set, entity, result.get("aliases", []))
        if self._enrich_fields:
            self._apply_entity_fields(self.helper.api.intrusion_set, entity, {
                "primary_motivation": normalize_motivation(result.get("motivation")),
                "resource_level": normalize_resource_level(result.get("resource_level")),
                "goals": result.get("goals") if isinstance(result.get("goals"), list) else None,
            })
        rel += self._link_software(entity_id, result, confidence)
        rel += self._link_attack_patterns(entity_id, result.get("attack_techniques", []), confidence)
        rel += self._link_vulnerabilities(entity_id, result.get("cves", []), confidence)
        rel += self._link_sectors(entity_id, result.get("targeted_sectors", []), confidence)
        rel += self._link_countries(entity_id, result.get("targeted_countries", []), confidence)
        rel += self._link_threat_actors(entity_id, result.get("threat_actors", []), confidence)
        return self._finalize(entity, "Intrusion-Set", result, confidence, rel, content_hash,
                              reenriched=content_hash is not None and self._reenriched)

    def _enrich_threat_actor(self, entity: dict, content_hash: "str | None" = None) -> str:
        content = self._prepare(entity)
        if content is None:
            return "Skipped: content too short"
        self._pending_before = self._snapshot_before(entity)
        result = self._call_gemini(THREAT_ACTOR_PROMPT, content, entity_type="threat-actor-group", entity=entity)
        if result is None:
            return "Skipped: Gemini error"
        confidence = self._parse_confidence(result)
        if self._confidence_decay_enabled:
            confidence = self._apply_age_decay(confidence, entity)
        entity_id = entity["id"]
        self._audit_detection("threat-actor-group", entity_id, result)
        self._src_type = "Threat-Actor-Group"
        if self._critic_enabled:
            self._run_critic(result, "threat-actor-group")
        rel = 0
        self._add_or_update_note(entity_id, result.get("summary", ""), confidence, content_hash)
        self._apply_aliases(self.helper.api.threat_actor_group, entity, result.get("aliases", []))
        if self._enrich_fields:
            self._apply_entity_fields(self.helper.api.threat_actor_group, entity, {
                "primary_motivation": normalize_motivation(result.get("motivation")),
                "sophistication": normalize_sophistication(result.get("sophistication")),
                "resource_level": normalize_resource_level(result.get("resource_level")),
                "goals": result.get("goals") if isinstance(result.get("goals"), list) else None,
            })
        rel += self._link_software(entity_id, result, confidence)
        rel += self._link_attack_patterns(entity_id, result.get("attack_techniques", []), confidence)
        rel += self._link_vulnerabilities(entity_id, result.get("cves", []), confidence)
        rel += self._link_sectors(entity_id, result.get("targeted_sectors", []), confidence)
        rel += self._link_countries(entity_id, result.get("targeted_countries", []), confidence)
        return self._finalize(entity, "Threat-Actor-Group", result, confidence, rel, content_hash,
                              reenriched=content_hash is not None and self._reenriched)

    def _enrich_malware(self, entity: dict, content_hash: "str | None" = None) -> str:
        content = self._prepare(entity)
        if content is None:
            return "Skipped: content too short"
        self._pending_before = self._snapshot_before(entity)
        result = self._call_gemini(MALWARE_PROMPT, content, entity_type="malware", entity=entity)
        if result is None:
            return "Skipped: Gemini error"
        confidence = self._parse_confidence(result)
        if self._confidence_decay_enabled:
            confidence = self._apply_age_decay(confidence, entity)
        entity_id = entity["id"]
        self._audit_detection("malware", entity_id, result)
        self._src_type = "Malware"
        if self._critic_enabled:
            self._run_critic(result, "malware")
        rel = 0
        self._add_or_update_note(entity_id, result.get("summary", ""), confidence, content_hash)
        if self._enrich_fields:
            self._apply_entity_fields(self.helper.api.malware, entity, {
                "malware_types": normalize_malware_types([result.get("malware_type")]),
                "implementation_languages": result.get("implementation_languages")
                    if isinstance(result.get("implementation_languages"), list) else None,
                "capabilities": result.get("capabilities")
                    if isinstance(result.get("capabilities"), list) else None,
            })
        rel += self._link_attack_patterns(entity_id, result.get("attack_techniques", []), confidence)
        rel += self._link_vulnerabilities(entity_id, result.get("cves", []), confidence)
        rel += self._link_sectors(entity_id, result.get("targeted_sectors", []), confidence)
        rel += self._link_threat_actors(entity_id, result.get("associated_threat_actors", []), confidence)
        return self._finalize(entity, "Malware", result, confidence, rel, content_hash,
                              reenriched=content_hash is not None and self._reenriched)

    def _enrich_campaign(self, entity: dict, content_hash: "str | None" = None) -> str:
        content = self._prepare(entity)
        if content is None:
            return "Skipped: content too short"
        self._pending_before = self._snapshot_before(entity)
        result = self._call_gemini(CAMPAIGN_PROMPT, content, entity_type="campaign", entity=entity)
        if result is None:
            return "Skipped: Gemini error"
        confidence = self._parse_confidence(result)
        if self._confidence_decay_enabled:
            confidence = self._apply_age_decay(confidence, entity)
        entity_id = entity["id"]
        self._audit_detection("campaign", entity_id, result)
        self._src_type = "Campaign"
        if self._critic_enabled:
            self._run_critic(result, "campaign")
        rel = 0
        c_summary = result.get("summary", "")
        c_affected = coerce_names(result.get("affected_products"))
        if c_affected:
            c_summary = (c_summary + "\n\nAffected products: " + ", ".join(c_affected)).strip()
        self._add_or_update_note(entity_id, c_summary, confidence, content_hash)
        if self._enrich_fields:
            self._apply_entity_fields(self.helper.api.campaign, entity, {
                "objective": result.get("objective") or None,
                "first_seen": result.get("first_seen") or None,
                "last_seen": result.get("last_seen") or None,
            })
        rel += self._link_attack_patterns(entity_id, result.get("attack_techniques", []), confidence)
        rel += self._link_software(entity_id, result, confidence)
        rel += self._link_vulnerabilities(entity_id, result.get("cves", []), confidence)
        rel += self._link_threat_actors(entity_id, result.get("threat_actors", []), confidence)
        rel += self._link_sectors(entity_id, result.get("targeted_sectors", []), confidence)
        rel += self._link_countries(entity_id, result.get("targeted_countries", []), confidence)
        return self._finalize(entity, "Campaign", result, confidence, rel, content_hash,
                              reenriched=content_hash is not None and self._reenriched)

    def _vuln_cvss_below_floor(self, entity: dict) -> bool:
        """True when AI_MIN_CVSS gating applies and the vulnerability's stored CVSS
        base score is below the floor. Auto-summarising low-severity standalone
        CVEs is low graph value; on-demand enrichment can still be forced by
        setting AI_MIN_CVSS=0. If no score is stored, we do NOT skip (unknown
        severity is treated as worth enriching)."""
        if self._min_cvss <= 0:
            return False
        raw = entity.get("x_opencti_cvss_base_score")
        if raw is None:
            raw = entity.get("x_opencti_base_score")
        try:
            if raw is None or str(raw).strip() == "":
                return False
            return float(raw) < self._min_cvss
        except (ValueError, TypeError):
            return False

    def _enrich_vulnerability(self, entity: dict, content_hash: "str | None" = None) -> str:
        content = self._prepare(entity)
        if content is None:
            return "Skipped: content too short"
        if self._vuln_cvss_below_floor(entity):
            self.helper.log_info(
                f"Skipping standalone vulnerability {entity.get('id')} "
                f"(CVSS below AI_MIN_CVSS floor {self._min_cvss})."
            )
            return "Skipped: below CVSS floor"
        self._pending_before = self._snapshot_before(entity)
        result = self._call_gemini(VULNERABILITY_PROMPT, content, entity_type="vulnerability", entity=entity)
        if result is None:
            return "Skipped: Gemini error"
        confidence = self._parse_confidence(result)
        if self._confidence_decay_enabled:
            confidence = self._apply_age_decay(confidence, entity)
        entity_id = entity["id"]
        self._audit_detection("vulnerability", entity_id, result)
        self._src_type = "Vulnerability"
        if self._critic_enabled:
            self._run_critic(result, "vulnerability")
        rel = 0
        summary = result.get("summary", "")
        cvss = result.get("cvss_score", "")
        # affected_software may come back as strings OR objects ({"name": ...}).
        affected = coerce_names(result.get("affected_software"))
        note_content = summary
        if cvss:
            note_content += f"\n\nCVSS Score: {cvss}"
        if affected:
            note_content += f"\n\nAffected Software: {', '.join(affected)}"
        self._add_or_update_note(entity_id, note_content, confidence, content_hash)
        if self._enrich_fields:
            vfields = {}
            try:
                if cvss and str(cvss).strip():
                    vfields["x_opencti_cvss_base_score"] = float(str(cvss).strip())
            except (ValueError, TypeError):
                pass
            sev = _norm_name(result.get("cvss_severity"))
            if sev in ("low", "medium", "high", "critical"):
                vfields["x_opencti_cvss_base_severity"] = sev.upper()
            try:
                epss = result.get("epss")
                if epss and str(epss).strip():
                    vfields["x_opencti_epss_score"] = float(str(epss).strip())
            except (ValueError, TypeError):
                pass
            self._apply_entity_fields(self.helper.api.vulnerability, entity, vfields)
        rel += self._link_attack_patterns(entity_id, result.get("attack_techniques", []), confidence)
        rel += self._link_threat_actors(entity_id, result.get("associated_threat_actors", []), confidence)
        return self._finalize(entity, "Vulnerability", result, confidence, rel, content_hash,
                              reenriched=content_hash is not None and self._reenriched)

    # ------------------------------------------------------------------
    # Message handler
    # ------------------------------------------------------------------

    def process_message(self, data: dict) -> str:  # noqa: C901
        """Entry point called by pycti for each RabbitMQ enrichment message."""
        if not isinstance(data, dict) or not data:
            self.helper.log_warning("Received invalid payload (not a non-empty dict). Skipping.")
            return "Skipped: invalid payload"

        entity_type = data.get("entity_type", "")
        if not entity_type or not isinstance(entity_type, str):
            self.helper.log_warning("Payload missing 'entity_type'. Skipping.")
            return "Skipped: missing entity_type"

        entity_id = data.get("entity_id", "")
        if not entity_id or not isinstance(entity_id, str):
            self.helper.log_warning("Payload missing 'entity_id'. Skipping.")
            return "Skipped: missing entity_id"

        enrichment_entity = data.get("enrichment_entity")
        if enrichment_entity is not None and not isinstance(enrichment_entity, dict):
            self.helper.log_warning(
                f"'enrichment_entity' is not a dict for entity {entity_id} — re-fetching from API."
            )
            enrichment_entity = None

        entity: "dict | None" = (
            enrichment_entity if isinstance(enrichment_entity, dict) and enrichment_entity else None
        )
        if not entity:
            try:
                entity = self._fetch_entity(entity_type.lower(), entity_id)
            except Exception as exc:  # noqa: BLE001
                self.helper.log_error(f"Failed to fetch entity {entity_id}: {exc}")
                return "Skipped: entity fetch failed"
            if not entity:
                self.helper.log_error(f"Entity {entity_id} not found or empty after fetch.")
                return "Skipped: entity fetch failed"

        # --- Feedback-loop guard ---
        # Never auto-enrich an entity this connector just created, nor its own
        # review-labelled stubs — that would create a self-referential cascade.
        if entity_id in self._self_created_ids:
            self.helper.log_info(f"Skipping self-created entity {entity_id} (loop guard).")
            return "Skipped: self-created (loop guard)"
        if self._has_review_label(entity):
            self.helper.log_info(
                f"Skipping AI-suggested stub {entity_id} (carries '{self._review_label}' label)."
            )
            return "Skipped: ai-suggested stub (loop guard)"

        # --- Content-hash re-enrichment decision ---
        current_hash = self._compute_entity_hash(entity)
        stored_hash = self._get_stored_hash(entity_id)
        if stored_hash is not None and stored_hash == current_hash:
            self.helper.log_info(
                f"Entity {entity_id} content unchanged since last enrichment (hash={current_hash}). Skipping."
            )
            return "Skipped: already enriched (unchanged)"
        # reenriched flag: previously enriched (a hash exists) but content changed
        self._reenriched = stored_hash is not None

        route_key = entity_type.lower()
        handler_map = {
            "report": self._enrich_report,
            "intrusion-set": self._enrich_intrusion_set,
            "threat-actor-group": self._enrich_threat_actor,
            "malware": self._enrich_malware,
            "campaign": self._enrich_campaign,
            "vulnerability": self._enrich_vulnerability,
        }
        handler = handler_map.get(route_key)
        if handler is None:
            return "Skipped: unsupported entity_type"

        with self._active_lock:
            self._active_enrichments += 1

        result_str = "Skipped: internal error"
        try:
            result_str = handler(entity, current_hash)
        except Exception as exc:  # noqa: BLE001
            self.helper.log_error(f"Unhandled exception enriching {entity_type} {entity_id}: {exc}")
            self.metrics.increment_error()
            if self.metrics.should_log_summary():
                self.helper.log_info(f"[METRICS] {self.metrics.summary_dict()}")
            return "Skipped: internal error"
        finally:
            with self._active_lock:
                self._active_enrichments -= 1

        if result_str.startswith("Enriched"):
            label_ok = self._apply_idempotency_label(entity_id)
            if not label_ok:
                result_str = "Enriched (label write failed)"
            self.metrics.increment_success()
        else:
            self.metrics.increment_error()

        if self.metrics.should_log_summary():
            self.helper.log_info(f"[METRICS] {self.metrics.summary_dict()}")
            self._persist_metrics()

        return result_str

    def _fetch_entity(self, entity_type_lower: str, entity_id: str) -> "dict | None":
        api = self.helper.api
        fetch_map = {
            "report": api.report.read,
            "intrusion-set": api.intrusion_set.read,
            "threat-actor-group": api.threat_actor_group.read,
            "malware": api.malware.read,
            "campaign": api.campaign.read,
            "vulnerability": api.vulnerability.read,
        }
        fetch_fn = fetch_map.get(entity_type_lower)
        if fetch_fn is None:
            return None
        return fetch_fn(id=entity_id)

    # ------------------------------------------------------------------
    # SIGTERM shutdown handler and start
    # ------------------------------------------------------------------

    def _make_shutdown_handler(self):
        connector = self

        def handler(signum, frame):  # noqa: ANN001
            connector._shutdown_flag = True
            connector.helper.log_info("SIGTERM received — stopping listener...")
            try:
                connector.helper.stop_listen()
            except Exception:  # noqa: BLE001
                pass

            with connector._active_lock:
                active = connector._active_enrichments
            connector.helper.log_info(f"SIGTERM received — draining {active} in-flight enrichments...")

            for iteration in range(30):
                with connector._active_lock:
                    active = connector._active_enrichments
                if active == 0:
                    break
                connector.helper.log_info(
                    f"Shutdown drain: {active} enrichment(s) still in progress (waited {iteration}s)..."
                )
                time.sleep(1)
            else:
                with connector._active_lock:
                    remaining = connector._active_enrichments
                if remaining > 0:
                    connector.helper.log_warning(
                        f"Shutdown drain timeout: {remaining} enrichment(s) did not complete within 30s."
                    )

            connector.helper.log_info(f"[METRICS FINAL] {connector.metrics.summary_dict()}")
            # Always snapshot on shutdown, not only every 100 enrichments, so a
            # restart never loses the run's performance record.
            connector._persist_metrics()
            sys.exit(0)

        return handler

    def start(self) -> None:
        signal.signal(signal.SIGTERM, self._make_shutdown_handler())
        self.helper.log_info(
            f"AI Enrichment (Gemini) connector starting... "
            f"(search_mode={self._search_mode}, search_content_floor={self._search_content_floor}, "
            f"model_high={self._model_high_name}, model_low={self._model_low_name})"
        )
        self.helper.listen(self.process_message)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    AIEnrichmentConnector().start()

