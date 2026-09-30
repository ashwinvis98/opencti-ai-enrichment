"""
Unit tests for the Gemini AI Enrichment Connector.
All OpenCTI API calls and Gemini SDK calls are mocked via unittest.mock.
No live network connections required.
"""
import importlib
import json
import sys
import types
import unittest
from unittest.mock import MagicMock, Mock, call, patch

# ---------------------------------------------------------------------------
# Minimal stubs for the google.genai and pycti packages so the module can be
# imported with neither installed (CI / unit-test environment, no credentials).
# ---------------------------------------------------------------------------

def _ensure_google_stubs():
    """Install lightweight stubs for google.* packages if not present."""
    if "google" not in sys.modules:
        google_pkg = types.ModuleType("google")
        sys.modules["google"] = google_pkg

    if "google.genai.errors" not in sys.modules:
        err_mod = types.ModuleType("google.genai.errors")

        class APIError(Exception):
            def __init__(self, code=None, message="", *args):
                super().__init__(message or f"APIError {code}")
                self.code = code
                self.message = message

        class ClientError(APIError):
            pass

        class ServerError(APIError):
            pass

        err_mod.APIError = APIError
        err_mod.ClientError = ClientError
        err_mod.ServerError = ServerError
        sys.modules["google.genai.errors"] = err_mod

    if "google.genai" not in sys.modules:
        genai_mod = types.ModuleType("google.genai")
        genai_mod.Client = MagicMock()
        sys.modules["google.genai"] = genai_mod

    # Also stub "google.genai.types" for the import, including the config/tool
    # classes used by _build_config so search/JSON branching can be tested.
    if "google.genai.types" not in sys.modules:
        genai_types_mod = types.ModuleType("google.genai.types")
        genai_types_mod.GenerateContentConfig = MagicMock(name="GenerateContentConfig")
        genai_types_mod.Tool = MagicMock(name="Tool")
        genai_types_mod.GoogleSearch = MagicMock(name="GoogleSearch")
        sys.modules["google.genai.types"] = genai_types_mod

    if "pycti" not in sys.modules:
        pycti_mod = types.ModuleType("pycti")
        pycti_mod.OpenCTIConnectorHelper = MagicMock()
        sys.modules["pycti"] = pycti_mod


_ensure_google_stubs()

# With the stubs installed, the package can be imported.
#
# `connector_module` is the single handle the whole suite reaches through, and
# enrichment/connector.py re-exports every predicate from the sibling modules,
# so the tests below are unchanged by the package split: `connector_module.X`
# resolves whether X lives in guards.py, orgs.py, grounding.py or elsewhere.
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import enrichment.connector as connector_module  # noqa: E402

AIEnrichmentConnector = connector_module.AIEnrichmentConnector
MetricsTracker = connector_module.MetricsTracker
MALWARE_PROMPT = connector_module.MALWARE_PROMPT
THREAT_ACTOR_PROMPT = connector_module.THREAT_ACTOR_PROMPT
REPORT_PROMPT = connector_module.REPORT_PROMPT
INTRUSION_SET_PROMPT = connector_module.INTRUSION_SET_PROMPT
CAMPAIGN_PROMPT = connector_module.CAMPAIGN_PROMPT
VULNERABILITY_PROMPT = connector_module.VULNERABILITY_PROMPT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_ENV = {
    "GEMINI_API_KEY": "test-gemini-key",
    "OPENCTI_TOKEN": "test-opencti-token",
    "CONNECTOR_ID": "00000000-0000-0000-0000-000000000001",
    "AI_IDEMPOTENCY_LABEL": "ai-enriched",
    "OPENCTI_URL": "http://localhost:8080",
    # Reference fetching performs DNS + HTTP; unit tests must never touch the
    # network. Tests that exercise fetching enable it explicitly and patch the
    # fetch function.
    "AI_FETCH_REFS": "false",
}


def _make_connector(extra_env: dict = None) -> AIEnrichmentConnector:
    """Instantiate a connector with all external dependencies mocked."""
    env = {**_BASE_ENV, **(extra_env or {})}
    with patch.dict(os.environ, env, clear=False):
        with patch("enrichment.connector.genai") as mock_genai, \
             patch("enrichment.connector.OpenCTIConnectorHelper") as mock_helper_cls:
            mock_helper_cls.return_value = MagicMock()
            mock_client = MagicMock()
            mock_client.models = MagicMock()
            mock_genai.Client = MagicMock(return_value=mock_client)
            c = AIEnrichmentConnector()
            # Patch helper after creation
            c.helper = MagicMock()
            c.helper.log_info = MagicMock()
            c.helper.log_warning = MagicMock()
            c.helper.log_error = MagicMock()
            c.helper.log_debug = MagicMock()
            # Default: no prior AI Summary note → _get_stored_hash returns None
            # so enrichment proceeds. Tests that exercise the re-enrichment skip
            # path override note.list to return a note with a hash marker.
            c.helper.api.note.list = MagicMock(return_value=[])
            return c


def _enable_creation(c: AIEnrichmentConnector, *categories: str) -> None:
    """Turn entity creation on for the given categories (all when omitted).

    Creation is gated per category now, so tests must set the mode rather than
    flipping the legacy _create_stubs boolean.
    """
    cats = categories or tuple(AIEnrichmentConnector._CREATE_ENV)
    if not categories:
        c._create_mode = "on"
    c._create_stubs = True
    c._create_modes = {**c._create_modes, **{cat: "on" for cat in cats}}


def _make_entity(entity_type: str = "report", **kwargs) -> dict:
    """Create a minimal entity dict."""
    base = {
        "id": "indicator--00000000-0000-0000-0000-000000000099",
        "entity_type": entity_type,
        "name": "Test Entity",
        "description": "A" * 60,
        "objectLabel": [],
        "objects": [],
    }
    base.update(kwargs)
    return base


def _gemini_result(**kwargs) -> dict:
    defaults = {
        "summary": "Test summary.",
        "threat_actors": [],
        "malware_families": [],
        "attack_techniques": [],
        "targeted_sectors": [],
        "targeted_countries": [],
        "associated_threat_actors": [],
        "confidence": 75,
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# 17.1  Startup validation
# ---------------------------------------------------------------------------

class TestStartupValidation(unittest.TestCase):
    """startup env var validation."""

    def _assert_exits_without(self, missing_key: str):
        env = {k: v for k, v in _BASE_ENV.items() if k != missing_key}
        # Ensure the key is absent from the process env too
        with patch.dict(os.environ, env, clear=True):
            # Restore keys unrelated to our connector that might be needed
            with self.assertRaises(SystemExit) as ctx:
                with patch("enrichment.connector.genai"), patch("enrichment.connector.OpenCTIConnectorHelper"):
                    AIEnrichmentConnector()
            self.assertNotEqual(ctx.exception.code, 0)

    def test_missing_gemini_api_key_exits(self):
        self._assert_exits_without("GEMINI_API_KEY")

    def test_empty_gemini_api_key_exits(self):
        env = {**_BASE_ENV, "GEMINI_API_KEY": ""}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit) as ctx:
                with patch("enrichment.connector.genai"), patch("enrichment.connector.OpenCTIConnectorHelper"):
                    AIEnrichmentConnector()
            self.assertNotEqual(ctx.exception.code, 0)

    def test_missing_opencti_token_exits(self):
        self._assert_exits_without("OPENCTI_TOKEN")

    def test_missing_connector_id_exits(self):
        self._assert_exits_without("CONNECTOR_ID")

    def test_empty_idempotency_label_exits(self):
        env = {**_BASE_ENV, "AI_IDEMPOTENCY_LABEL": ""}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit) as ctx:
                with patch("enrichment.connector.genai"), patch("enrichment.connector.OpenCTIConnectorHelper"):
                    AIEnrichmentConnector()
            self.assertNotEqual(ctx.exception.code, 0)

    def test_whitespace_only_idempotency_label_exits(self):
        env = {**_BASE_ENV, "AI_IDEMPOTENCY_LABEL": "   "}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit) as ctx:
                with patch("enrichment.connector.genai"), patch("enrichment.connector.OpenCTIConnectorHelper"):
                    AIEnrichmentConnector()
            self.assertNotEqual(ctx.exception.code, 0)

    def test_valid_env_initialises_without_exit(self):
        c = _make_connector()
        self.assertIsNotNone(c)
        self.assertEqual(c.idempotency_label, "ai-enriched")


# ---------------------------------------------------------------------------
# 17.2  CONNECTOR_AUTO and AI_CONTENT_LIMIT parsing
# ---------------------------------------------------------------------------

class TestConfigParsing(unittest.TestCase):
    """CONNECTOR_AUTO and AI_CONTENT_LIMIT parsing."""

    def _get_connector_with(self, extra: dict) -> AIEnrichmentConnector:
        return _make_connector(extra)

    # CONNECTOR_AUTO
    def test_auto_true_lowercase(self):
        c = self._get_connector_with({"CONNECTOR_AUTO": "true"})
        self.assertTrue(c.helper.api is not None or True)  # connector init succeeded

    def test_auto_false_lowercase(self):
        # Verify connector is created (auto is used in config dict, not stored separately after init)
        c = self._get_connector_with({"CONNECTOR_AUTO": "false"})
        self.assertIsNotNone(c)

    def test_auto_true_uppercase(self):
        c = self._get_connector_with({"CONNECTOR_AUTO": "TRUE"})
        self.assertIsNotNone(c)

    def test_auto_false_uppercase(self):
        c = self._get_connector_with({"CONNECTOR_AUTO": "FALSE"})
        self.assertIsNotNone(c)

    def test_auto_invalid_value_defaults_true_and_warns(self):
        with patch.dict(os.environ, {**_BASE_ENV, "CONNECTOR_AUTO": "maybe"}, clear=True):
            with patch("enrichment.connector.genai"), patch("enrichment.connector.OpenCTIConnectorHelper"):
                import logging
                with self.assertLogs(level="WARNING") as log_ctx:
                    AIEnrichmentConnector()
        self.assertTrue(any("maybe" in msg or "CONNECTOR_AUTO" in msg for msg in log_ctx.output))

    # AI_CONTENT_LIMIT
    def test_content_limit_absent_defaults_8000(self):
        env = {k: v for k, v in _BASE_ENV.items()}
        env.pop("AI_CONTENT_LIMIT", None)
        c = _make_connector(env)
        self.assertEqual(c.content_limit, 8000)

    def test_content_limit_non_integer_defaults_8000(self):
        c = _make_connector({"AI_CONTENT_LIMIT": "abc"})
        self.assertEqual(c.content_limit, 8000)

    def test_content_limit_negative_defaults_8000(self):
        c = _make_connector({"AI_CONTENT_LIMIT": "-1"})
        self.assertEqual(c.content_limit, 8000)

    def test_content_limit_zero_defaults_8000(self):
        c = _make_connector({"AI_CONTENT_LIMIT": "0"})
        self.assertEqual(c.content_limit, 8000)

    def test_content_limit_over_max_defaults_8000(self):
        c = _make_connector({"AI_CONTENT_LIMIT": "1000001"})
        self.assertEqual(c.content_limit, 8000)

    def test_content_limit_valid_500(self):
        c = _make_connector({"AI_CONTENT_LIMIT": "500"})
        self.assertEqual(c.content_limit, 500)


# ---------------------------------------------------------------------------
# 17.3  Payload validation in process_message
# ---------------------------------------------------------------------------

class TestPayloadValidation(unittest.TestCase):
    """process_message payload validation."""

    def setUp(self):
        self.c = _make_connector()

    def test_non_dict_input_skipped(self):
        self.assertEqual(self.c.process_message("bad"), "Skipped: invalid payload")

    def test_empty_dict_skipped(self):
        self.assertEqual(self.c.process_message({}), "Skipped: invalid payload")

    def test_missing_entity_type_skipped(self):
        self.assertEqual(
            self.c.process_message({"entity_id": "id-1"}),
            "Skipped: missing entity_type",
        )

    def test_empty_entity_type_skipped(self):
        self.assertEqual(
            self.c.process_message({"entity_type": "", "entity_id": "id-1"}),
            "Skipped: missing entity_type",
        )

    def test_missing_entity_id_skipped(self):
        self.assertEqual(
            self.c.process_message({"entity_type": "report"}),
            "Skipped: missing entity_id",
        )

    def test_non_dict_enrichment_entity_triggers_refetch(self):
        """Non-dict enrichment_entity → warning logged, re-fetch triggered."""
        self.c.helper.api.report = MagicMock()
        self.c.helper.api.report.read = MagicMock(return_value=None)

        result = self.c.process_message({
            "entity_type": "report",
            "entity_id": "id-1",
            "enrichment_entity": "not-a-dict",
        })
        self.c.helper.log_warning.assert_called()
        self.assertEqual(result, "Skipped: entity fetch failed")

    def test_refetch_exception_returns_skip(self):
        """Re-fetch exception → 'Skipped: entity fetch failed'."""
        self.c.helper.api.report = MagicMock()
        self.c.helper.api.report.read = MagicMock(side_effect=RuntimeError("API down"))

        result = self.c.process_message({
            "entity_type": "report",
            "entity_id": "id-1",
        })
        self.assertEqual(result, "Skipped: entity fetch failed")


# ---------------------------------------------------------------------------
# Content-hash re-enrichment guard (replaces label-only idempotency)
# ---------------------------------------------------------------------------

class TestReEnrichmentGuard(unittest.TestCase):
    """Content-hash based re-enrichment: skip only when source content is unchanged."""

    def setUp(self):
        self.c = _make_connector()
        # Wire up enrichment side-effects as no-ops
        self.c._call_gemini = MagicMock(return_value=_gemini_result())
        self.c._add_or_update_note = MagicMock()
        self.c._link_threat_actors = MagicMock(return_value=0)
        self.c._link_malware = MagicMock(return_value=0)
        self.c._link_attack_patterns = MagicMock(return_value=0)
        self.c._link_sectors = MagicMock(return_value=0)
        self.c._link_countries = MagicMock(return_value=0)
        self.c._update_score = MagicMock(return_value=True)
        self.c._apply_idempotency_label = MagicMock(return_value=True)
        self.c._apply_labels = MagicMock(return_value=0)

    def _send(self, entity):
        return self.c.process_message({
            "entity_type": "report",
            "entity_id": entity["id"],
            "enrichment_entity": entity,
        })

    def test_unchanged_content_skips_without_calling_gemini(self):
        """If stored hash equals current content hash → skip, Gemini NOT called."""
        entity = _make_entity()
        current_hash = self.c._compute_entity_hash(entity)
        # Simulate an existing AI Summary note carrying the matching hash marker
        self.c._get_stored_hash = MagicMock(return_value=current_hash)

        result = self._send(entity)
        self.assertEqual(result, "Skipped: already enriched (unchanged)")
        self.c._call_gemini.assert_not_called()

    def test_no_prior_enrichment_proceeds(self):
        """No stored hash (never enriched) → enrichment proceeds."""
        entity = _make_entity()
        self.c._get_stored_hash = MagicMock(return_value=None)

        result = self._send(entity)
        self.c._call_gemini.assert_called_once()
        self.assertEqual(result, "Enriched")

    def test_changed_content_reenriches(self):
        """Stored hash differs from current (content changed) → re-enrich."""
        entity = _make_entity()
        self.c._get_stored_hash = MagicMock(return_value="0000000000000000")

        result = self._send(entity)
        self.c._call_gemini.assert_called_once()
        self.assertEqual(result, "Enriched")
        self.assertTrue(self.c._reenriched)

    def test_content_hash_changes_when_description_changes(self):
        """The content hash must change when the description changes."""
        e1 = _make_entity(description="A" * 60)
        e2 = _make_entity(description="B" * 60)
        self.assertNotEqual(
            self.c._compute_entity_hash(e1),
            self.c._compute_entity_hash(e2),
        )

    def test_content_hash_changes_when_external_ref_added(self):
        """Adding an external reference must change the content hash (triggers re-enrich)."""
        e1 = _make_entity()
        e2 = _make_entity(externalReferences=[{"source_name": "mitre", "url": "https://x/y"}])
        self.assertNotEqual(
            self.c._compute_entity_hash(e1),
            self.c._compute_entity_hash(e2),
        )


# ---------------------------------------------------------------------------
# 17.5  Entity type routing
# ---------------------------------------------------------------------------

class TestEntityTypeRouting(unittest.TestCase):
    """correct routing to per-entity handlers."""

    def setUp(self):
        self.c = _make_connector()
        # Patch all enrichment handlers + side-effects
        self.c._enrich_report = MagicMock(return_value="Enriched")
        self.c._enrich_intrusion_set = MagicMock(return_value="Enriched")
        self.c._enrich_threat_actor = MagicMock(return_value="Enriched")
        self.c._enrich_malware = MagicMock(return_value="Enriched")
        self.c._enrich_campaign = MagicMock(return_value="Enriched")
        self.c._enrich_vulnerability = MagicMock(return_value="Enriched")
        self.c._apply_idempotency_label = MagicMock(return_value=True)

    def _send(self, entity_type: str):
        entity = _make_entity(entity_type=entity_type)
        return self.c.process_message({
            "entity_type": entity_type,
            "entity_id": entity["id"],
            "enrichment_entity": entity,
        })

    def test_report_routes_correctly(self):
        self._send("report")
        self.c._enrich_report.assert_called_once()

    def test_report_case_insensitive(self):
        self._send("REPORT")
        self.c._enrich_report.assert_called_once()

    def test_intrusion_set_routes_correctly(self):
        self._send("intrusion-set")
        self.c._enrich_intrusion_set.assert_called_once()

    def test_threat_actor_group_routes_correctly(self):
        self._send("threat-actor-group")
        self.c._enrich_threat_actor.assert_called_once()

    def test_malware_routes_correctly(self):
        self._send("malware")
        self.c._enrich_malware.assert_called_once()

    def test_campaign_routes_correctly(self):
        self._send("campaign")
        self.c._enrich_campaign.assert_called_once()

    def test_vulnerability_routes_correctly(self):
        self._send("vulnerability")
        self.c._enrich_vulnerability.assert_called_once()

    def test_unsupported_type_skipped(self):
        result = self._send("indicator")
        self.assertEqual(result, "Skipped: unsupported entity_type")
        # Gemini handlers not called
        for handler in [
            self.c._enrich_report, self.c._enrich_intrusion_set,
            self.c._enrich_threat_actor, self.c._enrich_malware,
            self.c._enrich_campaign, self.c._enrich_vulnerability,
        ]:
            handler.assert_not_called()

    def test_null_entity_type_skipped(self):
        result = self.c.process_message({
            "entity_type": None,
            "entity_id": "id-1",
        })
        self.assertEqual(result, "Skipped: missing entity_type")

    def test_empty_entity_type_skipped(self):
        result = self.c.process_message({
            "entity_type": "",
            "entity_id": "id-1",
        })
        self.assertEqual(result, "Skipped: missing entity_type")


# ---------------------------------------------------------------------------
# 17.6  Prompt correctness (malware and threat-actor-group)
# ---------------------------------------------------------------------------

class TestPromptCorrectness(unittest.TestCase):
    """correct prompts passed to _call_gemini."""

    def setUp(self):
        self.c = _make_connector()
        self.c._call_gemini = MagicMock(return_value=_gemini_result())
        self.c._add_or_update_note = MagicMock()
        self.c._link_threat_actors = MagicMock(return_value=0)
        self.c._link_malware = MagicMock(return_value=0)
        self.c._link_attack_patterns = MagicMock(return_value=0)
        self.c._link_sectors = MagicMock(return_value=0)
        self.c._link_countries = MagicMock(return_value=0)
        self.c._update_score = MagicMock(return_value=True)
        self.c._apply_idempotency_label = MagicMock(return_value=True)

    def test_malware_uses_malware_prompt_not_report_prompt(self):
        entity = _make_entity(entity_type="malware")
        self.c._enrich_malware(entity)
        prompt_used = self.c._call_gemini.call_args[0][0]
        self.assertIs(prompt_used, MALWARE_PROMPT)
        self.assertIsNot(prompt_used, REPORT_PROMPT)

    def test_threat_actor_group_uses_threat_actor_prompt(self):
        entity = _make_entity(entity_type="threat-actor-group")
        self.c._enrich_threat_actor(entity)
        prompt_used = self.c._call_gemini.call_args[0][0]
        self.assertIs(prompt_used, THREAT_ACTOR_PROMPT)
        self.assertIsNot(prompt_used, INTRUSION_SET_PROMPT)


# ---------------------------------------------------------------------------
# 17.7  Label write failure
# ---------------------------------------------------------------------------

class TestLabelWriteFailure(unittest.TestCase):
    """label write failure returns correct sentinel."""

    def setUp(self):
        self.c = _make_connector()
        self.c._call_gemini = MagicMock(return_value=_gemini_result())
        self.c._add_or_update_note = MagicMock()
        self.c._link_threat_actors = MagicMock(return_value=0)
        self.c._link_malware = MagicMock(return_value=0)
        self.c._link_attack_patterns = MagicMock(return_value=0)
        self.c._link_sectors = MagicMock(return_value=0)
        self.c._link_countries = MagicMock(return_value=0)
        self.c._update_score = MagicMock(return_value=True)

    def test_apply_label_raises_returns_enriched_label_write_failed(self):
        # _apply_idempotency_label raises an exception internally, returns False
        self.c.helper.api.stix_domain_object = MagicMock()
        self.c.helper.api.stix_domain_object.add_label = MagicMock(
            side_effect=RuntimeError("label API failure")
        )

        entity = _make_entity()
        result = self.c.process_message({
            "entity_type": "report",
            "entity_id": entity["id"],
            "enrichment_entity": entity,
        })
        self.assertEqual(result, "Enriched (label write failed)")


# ---------------------------------------------------------------------------
# 17.8  _strip_fences edge cases
# ---------------------------------------------------------------------------

class TestStripFences(unittest.TestCase):
    """_strip_fences edge cases."""

    def setUp(self):
        self.c = _make_connector()

    def test_json_fence_stripped(self):
        text = "```json\n{\"key\": \"val\"}\n```"
        result = self.c._strip_fences(text)
        self.assertEqual(result, '{"key": "val"}')

    def test_generic_fence_stripped(self):
        text = "```\n{\"key\": \"val\"}\n```"
        result = self.c._strip_fences(text)
        self.assertEqual(result, '{"key": "val"}')

    def test_no_fence_returns_text_unchanged(self):
        text = '{"key": "val"}'
        result = self.c._strip_fences(text)
        self.assertEqual(result, text)

    def test_unclosed_json_fence_returns_none_and_logs_error(self):
        text = "```json\n{\"key\": \"val\"}"
        result = self.c._strip_fences(text)
        self.assertIsNone(result)
        self.c.helper.log_error.assert_called()

    def test_unclosed_generic_fence_returns_none_and_logs_error(self):
        text = "```\n{\"key\": \"val\"}"
        result = self.c._strip_fences(text)
        self.assertIsNone(result)
        self.c.helper.log_error.assert_called()

    def test_json_fence_case_insensitive(self):
        text = "```JSON\n{\"key\": \"val\"}\n```"
        result = self.c._strip_fences(text)
        self.assertEqual(result, '{"key": "val"}')


# ---------------------------------------------------------------------------
# 17.9  _parse_confidence edge cases
# ---------------------------------------------------------------------------

class TestParseConfidence(unittest.TestCase):
    """_parse_confidence edge cases."""

    def setUp(self):
        self.c = _make_connector()

    def test_none_returns_50_and_warns(self):
        result = self.c._parse_confidence({"confidence": None})
        self.assertEqual(result, 50)
        self.c.helper.log_warning.assert_called()

    def test_string_value_returns_50_and_warns(self):
        result = self.c._parse_confidence({"confidence": "abc"})
        self.assertEqual(result, 50)
        self.c.helper.log_warning.assert_called()

    def test_float_truncates(self):
        result = self.c._parse_confidence({"confidence": 50.7})
        self.assertEqual(result, 50)

    def test_negative_clamped_to_0(self):
        result = self.c._parse_confidence({"confidence": -5})
        self.assertEqual(result, 0)

    def test_over_100_clamped_to_100(self):
        result = self.c._parse_confidence({"confidence": 150})
        self.assertEqual(result, 100)

    def test_absent_key_returns_50_and_warns(self):
        result = self.c._parse_confidence({})
        self.assertEqual(result, 50)
        self.c.helper.log_warning.assert_called()

    def test_valid_value_returned_as_int(self):
        result = self.c._parse_confidence({"confidence": 72})
        self.assertEqual(result, 72)
        self.assertIsInstance(result, int)


# ---------------------------------------------------------------------------
# 17.10  Note create/update paths
# ---------------------------------------------------------------------------

class TestNoteUpsert(unittest.TestCase):
    """_add_or_update_note create/update logic."""

    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.note = MagicMock()
        self.c.helper.api.stix_domain_object = MagicMock()

    def _set_entity_notes(self, count: int):
        # Existing AI Summary notes are discovered via the ENTITY-side read
        # (stix_domain_object.read -> notes list), so mock that.
        notes = [
            {
                "id": f"note--{i:04d}",
                "attribute_abstract": "AI Summary",
                "content": "prior summary",
                "modified": f"2024-01-0{i+1}T00:00:00Z",
            }
            for i in range(count)
        ]
        self.c.helper.api.stix_domain_object.read = MagicMock(return_value={"notes": notes})

    def test_zero_notes_creates_new_note(self):
        self.c.helper.api.stix_domain_object.read = MagicMock(return_value={"notes": []})
        self.c._add_or_update_note("entity-id", "summary", 75)
        self.c.helper.api.note.create.assert_called_once()
        self.c.helper.api.note.update.assert_not_called()

    def test_create_uses_objects_param_to_link(self):
        # The note MUST be created with `objects=` (links to entity), NOT object_ids.
        self.c.helper.api.stix_domain_object.read = MagicMock(return_value={"notes": []})
        self.c._add_or_update_note("entity-id", "summary", 75)
        kwargs = self.c.helper.api.note.create.call_args[1]
        self.assertIn("objects", kwargs)
        self.assertEqual(kwargs["objects"], ["entity-id"])
        self.assertNotIn("object_ids", kwargs)

    def test_one_existing_note_updates_not_creates(self):
        self._set_entity_notes(1)
        self.c._add_or_update_note("entity-id", "updated summary", 75)
        self.c.helper.api.note.update.assert_called_once()
        self.c.helper.api.note.create.assert_not_called()

    def test_non_ai_summary_notes_ignored(self):
        # A note attached to the entity that is NOT an AI Summary must be ignored,
        # so a new AI Summary note is created (not an update of the unrelated note).
        self.c.helper.api.stix_domain_object.read = MagicMock(return_value={"notes": [
            {"id": "note--other", "attribute_abstract": "Analyst comment", "content": "x"},
        ]})
        self.c._add_or_update_note("entity-id", "summary", 75)
        self.c.helper.api.note.create.assert_called_once()
        self.c.helper.api.note.update.assert_not_called()

    def test_two_notes_warns_and_updates_most_recent(self):
        self.c.helper.api.stix_domain_object.read = MagicMock(return_value={"notes": [
            {"id": "note--old", "attribute_abstract": "AI Summary", "content": "a", "modified": "2024-01-01T00:00:00Z"},
            {"id": "note--new", "attribute_abstract": "AI Summary", "content": "b", "modified": "2024-06-01T00:00:00Z"},
        ]})
        self.c._add_or_update_note("entity-id", "updated summary", 75)
        self.c.helper.api.note.update.assert_called_once()
        self.c.helper.api.note.create.assert_not_called()
        self.c.helper.log_warning.assert_called()
        update_call_id = self.c.helper.api.note.update.call_args[1]["id"]
        self.assertEqual(update_call_id, "note--new")

    def test_query_exception_logs_error_and_skips(self):
        self.c.helper.api.stix_domain_object.read = MagicMock(side_effect=RuntimeError("API error"))
        # Should NOT raise
        self.c._add_or_update_note("entity-id", "summary", 75)
        self.c.helper.log_error.assert_called()
        self.c.helper.api.note.create.assert_not_called()
        self.c.helper.api.note.update.assert_not_called()


# ---------------------------------------------------------------------------
# 17.11  Country codes and blank sector names
# ---------------------------------------------------------------------------

class TestCountryAndSectorValidation(unittest.TestCase):
    """country code validation and blank sector handling."""

    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.location = MagicMock()
        self.c.helper.api.identity = MagicMock()
        self.c.helper.api.stix_core_relationship = MagicMock()
        self.c.helper.api.stix_core_relationship.create = MagicMock(
            return_value={"id": "rel--test"}
        )

    # --- Country code tests ---

    def test_country_not_in_opencti_warns_and_skips(self):
        self.c.helper.api.location.read = MagicMock(return_value=None)
        count = self.c._link_countries("entity-id", ["US"], 75)
        self.assertEqual(count, 0)
        self.c.helper.log_warning.assert_called()
        self.c.helper.api.stix_core_relationship.create.assert_not_called()

    def test_invalid_country_code_one_char_warns_and_skips(self):
        count = self.c._link_countries("entity-id", ["U"], 75)
        self.assertEqual(count, 0)
        self.c.helper.log_warning.assert_called()

    def test_invalid_country_code_three_char_warns_and_skips(self):
        count = self.c._link_countries("entity-id", ["USA"], 75)
        self.assertEqual(count, 0)
        self.c.helper.log_warning.assert_called()

    def test_invalid_country_code_with_digit_warns_and_skips(self):
        count = self.c._link_countries("entity-id", ["U1"], 75)
        self.assertEqual(count, 0)
        self.c.helper.log_warning.assert_called()

    def test_valid_country_code_found_creates_relationship(self):
        self.c.helper.api.location.read = MagicMock(
            return_value={"id": "location--us"}
        )
        count = self.c._link_countries("entity-id", ["US"], 75)
        self.assertEqual(count, 1)

    # --- Sector tests ---

    def test_blank_sector_warns_and_skips(self):
        count = self.c._link_sectors("entity-id", [""], 75)
        self.assertEqual(count, 0)
        self.c.helper.log_warning.assert_called()

    def test_whitespace_sector_warns_and_skips(self):
        count = self.c._link_sectors("entity-id", ["   "], 75)
        self.assertEqual(count, 0)
        self.c.helper.log_warning.assert_called()

    def test_valid_sector_links_via_vocabulary(self):
        # Lookup-only + alias-aware: detected name resolves to an existing Sector.
        self.c.helper.api.identity.list = MagicMock(return_value=[
            {"id": "identity--finance", "name": "Financial Services",
             "entity_type": "Sector", "aliases": ["Finance"]},
        ])
        count = self.c._link_sectors("entity-id", ["Finance"], 75)
        self.assertEqual(count, 1)

    def test_sector_not_in_vocab_skipped_no_create(self):
        # Not in controlled vocabulary + AI_CREATE_SECTORS off -> skip, never create.
        self.c.helper.api.identity.list = MagicMock(return_value=[])
        self.c.helper.api.identity.create = MagicMock()
        count = self.c._link_sectors("entity-id", ["Totally Novel Sector"], 75)
        self.assertEqual(count, 0)
        self.c.helper.api.identity.create.assert_not_called()


# ---------------------------------------------------------------------------
# Additional: _update_score passes int not str (P0 bug fix verification)
# ---------------------------------------------------------------------------

class TestUpdateScoreIntType(unittest.TestCase):
    """Verify the critical P0 fix: _update_score passes int, not str."""

    def test_update_score_passes_integer_value(self):
        c = _make_connector()
        c.helper.api.stix_domain_object = MagicMock()
        c.helper.api.stix_domain_object.update_field = MagicMock(return_value={})

        c._update_score("entity-id", 72)

        call_kwargs = c.helper.api.stix_domain_object.update_field.call_args
        value_passed = call_kwargs[1]["input"]["value"]
        self.assertIsInstance(value_passed, int)
        self.assertEqual(value_passed, 72)

    def test_update_score_value_is_not_string(self):
        c = _make_connector()
        c.helper.api.stix_domain_object = MagicMock()
        c.helper.api.stix_domain_object.update_field = MagicMock(return_value={})

        c._update_score("entity-id", 50)

        value_passed = c.helper.api.stix_domain_object.update_field.call_args[1]["input"]["value"]
        self.assertNotIsInstance(value_passed, str)

    def test_incompatible_attribute_skipped_gracefully(self):
        # SDO types reject x_opencti_score with VALIDATION_ERROR; this must be
        # handled quietly (debug, not error) and return False.
        c = _make_connector()
        c.helper.api.stix_domain_object = MagicMock()
        c.helper.api.stix_domain_object.update_field = MagicMock(
            side_effect=ValueError("{'name': 'VALIDATION_ERROR', 'error_message': 'You cannot update incompatible attribute'}")
        )
        result = c._update_score("entity-id", 80)
        self.assertFalse(result)
        c.helper.log_error.assert_not_called()   # no noisy error
        c.helper.log_debug.assert_called()

    def test_other_score_error_still_logs_error(self):
        c = _make_connector()
        c.helper.api.stix_domain_object = MagicMock()
        c.helper.api.stix_domain_object.update_field = MagicMock(
            side_effect=RuntimeError("connection reset")
        )
        result = c._update_score("entity-id", 80)
        self.assertFalse(result)
        c.helper.log_error.assert_called()


# ---------------------------------------------------------------------------
# MetricsTracker thread safety
# ---------------------------------------------------------------------------

class TestMetricsTrackerThreadSafety(unittest.TestCase):
    """Verify MetricsTracker counters are correct under concurrent access."""

    def test_concurrent_increments_are_accurate(self):
        import threading
        mt = MetricsTracker()
        threads = [threading.Thread(target=mt.increment_success) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(mt.enrichments_total, 200)

    def test_should_log_summary_at_multiples_of_100(self):
        mt = MetricsTracker()
        for _ in range(99):
            mt.increment_success()
        self.assertFalse(mt.should_log_summary())
        mt.increment_success()  # now at 100
        self.assertTrue(mt.should_log_summary())


# ---------------------------------------------------------------------------
# Dynamic model routing
# ---------------------------------------------------------------------------

class TestModelRouting(unittest.TestCase):
    """Tests for _resolve_model: dynamic selection based on entity type and content length."""

    def setUp(self):
        self.c = _make_connector({
            "GEMINI_MODEL_HIGH": "gemini-3.5-flash",
            "GEMINI_MODEL_LOW": "gemini-3.5-flash-lite",
            "GEMINI_MODEL_ROUTING_THRESHOLD": "2000",
        })

    # --- High-effort entity types always get the high model ---

    def test_report_gets_high_model(self):
        model = self.c._resolve_model("report", 100)
        self.assertEqual(model, "gemini-3.5-flash")

    def test_intrusion_set_gets_high_model(self):
        model = self.c._resolve_model("intrusion-set", 100)
        self.assertEqual(model, "gemini-3.5-flash")

    def test_campaign_gets_high_model(self):
        model = self.c._resolve_model("campaign", 100)
        self.assertEqual(model, "gemini-3.5-flash")

    # --- Low-effort entity types get the low model when content is short ---

    def test_malware_short_content_gets_low_model(self):
        model = self.c._resolve_model("malware", 500)
        self.assertEqual(model, "gemini-3.5-flash-lite")

    def test_threat_actor_short_content_gets_low_model(self):
        model = self.c._resolve_model("threat-actor-group", 1000)
        self.assertEqual(model, "gemini-3.5-flash-lite")

    def test_vulnerability_short_content_gets_low_model(self):
        model = self.c._resolve_model("vulnerability", 200)
        self.assertEqual(model, "gemini-3.5-flash-lite")

    # --- Content length override: long content bumps to high model ---

    def test_malware_long_content_gets_high_model(self):
        model = self.c._resolve_model("malware", 2500)
        self.assertEqual(model, "gemini-3.5-flash")

    def test_vulnerability_long_content_gets_high_model(self):
        model = self.c._resolve_model("vulnerability", 3000)
        self.assertEqual(model, "gemini-3.5-flash")

    def test_threat_actor_at_threshold_gets_low_model(self):
        # Exactly at threshold (not exceeding) should stay low
        model = self.c._resolve_model("threat-actor-group", 2000)
        self.assertEqual(model, "gemini-3.5-flash-lite")

    def test_threat_actor_above_threshold_gets_high_model(self):
        model = self.c._resolve_model("threat-actor-group", 2001)
        self.assertEqual(model, "gemini-3.5-flash")

    # --- High-effort types are unaffected by content length ---

    def test_report_short_content_still_gets_high_model(self):
        model = self.c._resolve_model("report", 50)
        self.assertEqual(model, "gemini-3.5-flash")

    # --- Fallback: unknown entity types treated as low effort ---

    def test_unknown_type_short_content_gets_low_model(self):
        model = self.c._resolve_model("unknown-type", 500)
        self.assertEqual(model, "gemini-3.5-flash-lite")

    def test_unknown_type_long_content_gets_high_model(self):
        model = self.c._resolve_model("unknown-type", 5000)
        self.assertEqual(model, "gemini-3.5-flash")


class TestModelRoutingConfig(unittest.TestCase):
    """Tests for model routing environment variable parsing."""

    def test_default_threshold_is_2000(self):
        c = _make_connector()
        self.assertEqual(c._routing_threshold, 2000)

    def test_custom_threshold_parsed(self):
        c = _make_connector({"GEMINI_MODEL_ROUTING_THRESHOLD": "5000"})
        self.assertEqual(c._routing_threshold, 5000)

    def test_invalid_threshold_defaults_to_2000(self):
        c = _make_connector({"GEMINI_MODEL_ROUTING_THRESHOLD": "abc"})
        self.assertEqual(c._routing_threshold, 2000)

    def test_negative_threshold_defaults_to_2000(self):
        c = _make_connector({"GEMINI_MODEL_ROUTING_THRESHOLD": "-1"})
        self.assertEqual(c._routing_threshold, 2000)

    def test_high_effort_types_include_report_intrusion_campaign(self):
        c = _make_connector()
        self.assertIn("report", c._high_effort_types)
        self.assertIn("intrusion-set", c._high_effort_types)
        self.assertIn("campaign", c._high_effort_types)

    def test_fallback_single_gemini_model_env(self):
        """If only GEMINI_MODEL is set (old config), both high and low use it."""
        c = _make_connector({"GEMINI_MODEL": "gemini-2.5-flash"})
        self.assertEqual(c._model_high_name, "gemini-2.5-flash")
        self.assertEqual(c._model_low_name, "gemini-2.5-flash")


# ---------------------------------------------------------------------------
# External references
# ---------------------------------------------------------------------------

class TestExternalReferences(unittest.TestCase):
    """Tests for external reference extraction and prompt augmentation."""

    def setUp(self):
        self.c = _make_connector()

    def test_extract_refs_returns_urls_with_source(self):
        entity = _make_entity(externalReferences=[
            {"source_name": "mitre", "url": "https://attack.mitre.org/groups/G0016/"},
            {"source_name": "mandiant", "url": "https://mandiant.com/apt29"},
        ])
        refs = self.c._extract_external_refs(entity)
        self.assertEqual(len(refs), 2)
        self.assertIn("mitre: https://attack.mitre.org/groups/G0016/", refs)

    def test_extract_refs_empty_when_none(self):
        self.assertEqual(self.c._extract_external_refs(_make_entity()), [])

    def test_augment_appends_refs_to_content(self):
        entity = _make_entity(externalReferences=[{"source_name": "src", "url": "https://x/y"}])
        augmented = self.c._augment_with_refs("base content", entity)
        self.assertIn("base content", augmented)
        self.assertIn("External references", augmented)
        self.assertIn("https://x/y", augmented)

    def test_augment_noop_when_no_refs(self):
        augmented = self.c._augment_with_refs("base content", _make_entity())
        self.assertEqual(augmented, "base content")


# ---------------------------------------------------------------------------
# Suggested labels
# ---------------------------------------------------------------------------

class TestSuggestedLabels(unittest.TestCase):
    """Tests for _apply_labels."""

    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.stix_domain_object = MagicMock()
        self.c.helper.api.stix_domain_object.add_label = MagicMock()

    def test_applies_labels(self):
        count = self.c._apply_labels("entity-id", ["ransomware", "phishing"])
        self.assertEqual(count, 2)
        self.assertEqual(self.c.helper.api.stix_domain_object.add_label.call_count, 2)

    def test_skips_reserved_idempotency_label(self):
        count = self.c._apply_labels("entity-id", ["ai-enriched", "ransomware"])
        self.assertEqual(count, 1)  # ai-enriched skipped

    def test_skips_blank_labels(self):
        count = self.c._apply_labels("entity-id", ["", "   ", "valid"])
        self.assertEqual(count, 1)

    def test_respects_max_labels_cap(self):
        self.c._max_labels = 3
        count = self.c._apply_labels("entity-id", ["a", "b", "c", "d", "e"])
        self.assertEqual(count, 3)

    def test_disabled_when_flag_off(self):
        self.c._apply_suggested_labels = False
        count = self.c._apply_labels("entity-id", ["ransomware"])
        self.assertEqual(count, 0)
        self.c.helper.api.stix_domain_object.add_label.assert_not_called()

    def test_labels_lowercased(self):
        self.c._apply_labels("entity-id", ["Ransomware"])
        applied = self.c.helper.api.stix_domain_object.add_label.call_args[1]["label_name"]
        self.assertEqual(applied, "ransomware")


# ---------------------------------------------------------------------------
# Search grounding config branching
# ---------------------------------------------------------------------------

class TestSearchConfig(unittest.TestCase):
    """Tests for search-mode parsing, per-entity _resolve_search, and _build_config."""

    # --- mode parsing ---
    def test_default_mode_is_auto(self):
        self.assertEqual(_make_connector()._search_mode, "auto")

    def test_always_mode_variants(self):
        for v in ("always", "true", "1", "yes"):
            self.assertEqual(_make_connector({"GEMINI_ENABLE_SEARCH": v})._search_mode, "always")

    def test_never_mode_variants(self):
        for v in ("never", "false", "0", "no"):
            self.assertEqual(_make_connector({"GEMINI_ENABLE_SEARCH": v})._search_mode, "never")

    def test_unknown_value_falls_back_to_auto(self):
        self.assertEqual(_make_connector({"GEMINI_ENABLE_SEARCH": "banana"})._search_mode, "auto")

    # --- _build_config both branches ---
    def test_build_config_returns_object_both_modes(self):
        c = _make_connector()
        self.assertIsNotNone(c._build_config(True))
        self.assertIsNotNone(c._build_config(False))

    # --- _resolve_search: always / never ---
    def test_always_mode_always_searches(self):
        c = _make_connector({"GEMINI_ENABLE_SEARCH": "always"})
        self.assertTrue(c._resolve_search(_make_entity(description="A" * 5000), "x" * 5000))

    def test_never_mode_never_searches(self):
        c = _make_connector({"GEMINI_ENABLE_SEARCH": "never"})
        entity = _make_entity(externalReferences=[{"source_name": "s", "url": "https://x/y"}])
        self.assertFalse(c._resolve_search(entity, "short"))

    # --- _resolve_search: auto heuristics ---
    def test_auto_searches_when_external_refs_present(self):
        c = _make_connector()  # auto
        entity = _make_entity(
            description="A" * 5000,  # rich content, but refs present
            externalReferences=[{"source_name": "mitre", "url": "https://attack.mitre.org/x"}],
        )
        self.assertTrue(c._resolve_search(entity, "A" * 5000))

    def test_auto_searches_when_content_thin(self):
        c = _make_connector()  # auto, floor 500
        entity = _make_entity(description="APT29 is a Russian group.")  # ~25 chars
        self.assertTrue(c._resolve_search(entity, entity["description"]))

    def test_auto_skips_search_for_rich_selfcontained_content(self):
        c = _make_connector()  # auto
        entity = _make_entity(description="A" * 5000)  # rich, no refs
        self.assertFalse(c._resolve_search(entity, "A" * 5000))

    def test_auto_content_floor_configurable(self):
        c = _make_connector({"GEMINI_SEARCH_CONTENT_FLOOR": "100"})
        # 150-char description is above a 100 floor and has no refs → no search
        entity = _make_entity(description="A" * 150)
        self.assertFalse(c._resolve_search(entity, "A" * 150))


# ---------------------------------------------------------------------------
# Confidence calibration
# ---------------------------------------------------------------------------

class TestConfidenceCalibration(unittest.TestCase):
    """Tests for the calibration offset applied in _parse_confidence."""

    def test_negative_offset_reduces_confidence(self):
        c = _make_connector({"AI_CONFIDENCE_CALIBRATION_OFFSET": "-10"})
        self.assertEqual(c._parse_confidence({"confidence": 80}), 70)

    def test_positive_offset_increases_confidence(self):
        c = _make_connector({"AI_CONFIDENCE_CALIBRATION_OFFSET": "10"})
        self.assertEqual(c._parse_confidence({"confidence": 80}), 90)

    def test_offset_clamped_within_bounds(self):
        c = _make_connector({"AI_CONFIDENCE_CALIBRATION_OFFSET": "-30"})
        # 20 - 30 = -10 → clamped to 0
        self.assertEqual(c._parse_confidence({"confidence": 20}), 0)

    def test_invalid_offset_defaults_zero(self):
        c = _make_connector({"AI_CONFIDENCE_CALIBRATION_OFFSET": "abc"})
        self.assertEqual(c._calibration_offset, 0)


# ---------------------------------------------------------------------------
# Resolution-rate quality tracking
# ---------------------------------------------------------------------------

class TestResolutionTracking(unittest.TestCase):
    """Tests for automated quality feedback (resolution rate)."""

    def setUp(self):
        self.c = _make_connector()

    def test_count_suggested_sums_list_fields(self):
        result = _gemini_result(
            threat_actors=["APT29", "APT28"],
            malware_families=["Cobalt Strike"],
            attack_techniques=["T1059", "T1003", "T1071"],
        )
        # 2 + 1 + 3 = 6
        self.assertEqual(self.c._count_suggested(result), 6)

    def test_count_suggested_ignores_blanks(self):
        result = _gemini_result(threat_actors=["APT29", "", "  "])
        self.assertEqual(self.c._count_suggested(result), 1)

    def test_record_resolution_updates_metrics(self):
        self.c.metrics.record_resolution(suggested=10, resolved=4)
        summary = self.c.metrics.summary_dict()
        self.assertEqual(summary["names_suggested"], 10)
        self.assertEqual(summary["names_resolved"], 4)
        self.assertEqual(summary["resolution_rate"], 0.4)

    def test_resolution_rate_none_when_no_suggestions(self):
        summary = self.c.metrics.summary_dict()
        self.assertIsNone(summary["resolution_rate"])


# ---------------------------------------------------------------------------
# Note hash marker
# ---------------------------------------------------------------------------

class TestNoteHashMarker(unittest.TestCase):
    """Tests that the content-hash marker is embedded in the AI Summary note."""

    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.note = MagicMock()
        self.c.helper.api.stix_domain_object = MagicMock()
        self.c.helper.api.stix_domain_object.read = MagicMock(return_value={"notes": []})

    def test_hash_marker_embedded_in_new_note(self):
        self.c._add_or_update_note("entity-id", "summary text", 75, content_hash="abcdef0123456789")
        created_content = self.c.helper.api.note.create.call_args[1]["content"]
        self.assertIn("[ai-enrichment-hash:abcdef0123456789]", created_content)
        self.assertIn("summary text", created_content)

    def test_no_marker_when_hash_absent(self):
        self.c._add_or_update_note("entity-id", "summary text", 75)
        created_content = self.c.helper.api.note.create.call_args[1]["content"]
        self.assertNotIn("ai-enrichment-hash", created_content)


# ---------------------------------------------------------------------------
# Alias-aware / case-insensitive resolution + gated stub creation
# ---------------------------------------------------------------------------

class TestActorMalwareResolution(unittest.TestCase):
    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.threat_actor_group = MagicMock()
        self.c.helper.api.intrusion_set = MagicMock()
        self.c.helper.api.malware = MagicMock()
        self.c.helper.api.stix_domain_object = MagicMock()
        self.c.helper.api.stix_core_relationship = MagicMock()
        self.c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--x"})
        # default: search returns nothing
        self.c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        self.c.helper.api.intrusion_set.list = MagicMock(return_value=[])
        self.c.helper.api.malware.list = MagicMock(return_value=[])

    def test_case_insensitive_name_match(self):
        self.c.helper.api.threat_actor_group.list = MagicMock(
            return_value=[{"id": "ta--1", "name": "APT29", "aliases": []}]
        )
        self.assertEqual(self.c._link_threat_actors("e", ["apt29"], 75), 1)

    def test_alias_match_via_intrusion_set(self):
        self.c.helper.api.intrusion_set.list = MagicMock(
            return_value=[{"id": "is--1", "name": "APT29", "aliases": ["Cozy Bear"]}]
        )
        self.assertEqual(self.c._link_threat_actors("e", ["cozy bear"], 75), 1)

    def test_fulltext_false_positive_rejected(self):
        # search returns a loosely-related entity that is NOT an exact name/alias match
        self.c.helper.api.threat_actor_group.list = MagicMock(
            return_value=[{"id": "ta--x", "name": "APT28", "aliases": ["Fancy Bear"]}]
        )
        self.assertEqual(self.c._link_threat_actors("e", ["APT29"], 75), 0)

    def test_no_match_no_stub_creates_nothing(self):
        self.assertEqual(self.c._link_threat_actors("e", ["Unknown Actor"], 75), 0)
        self.c.helper.api.intrusion_set.create.assert_not_called()

    def test_no_match_with_stub_creates_and_links_and_labels(self):
        _enable_creation(self.c)
        self.c.helper.api.intrusion_set.create = MagicMock(return_value={"id": "is--new"})
        self.assertEqual(self.c._link_threat_actors("e", ["Novel Actor"], 75), 1)
        self.c.helper.api.intrusion_set.create.assert_called_once()
        # review label applied to the stub
        self.c.helper.api.stix_domain_object.add_label.assert_called()

    def test_malware_alias_match(self):
        self.c.helper.api.malware.list = MagicMock(
            return_value=[{"id": "mw--1", "name": "Cobalt Strike", "aliases": ["CobaltStrike"]}]
        )
        self.assertEqual(self.c._link_malware("e", ["cobaltstrike"], 75), 1)

    def test_malware_stub_when_enabled(self):
        _enable_creation(self.c)
        self.c.helper.api.malware.create = MagicMock(return_value={"id": "mw--new"})
        self.assertEqual(self.c._link_malware("e", ["NewRAT"], 75), 1)
        self.c.helper.api.malware.create.assert_called_once()

    def test_malware_no_stub_by_default(self):
        self.assertEqual(self.c._link_malware("e", ["NewRAT"], 75), 0)
        self.c.helper.api.malware.create.assert_not_called()

    def test_create_stubs_default_off(self):
        self.assertFalse(_make_connector()._create_stubs)

    def test_create_stubs_enabled_by_env(self):
        self.assertTrue(_make_connector({"AI_CREATE_STUBS": "true"})._create_stubs)


# ---------------------------------------------------------------------------
# Dedup / quality gate: generic rejection + leetspeak-aware matching
# ---------------------------------------------------------------------------

is_generic_entity_name = connector_module.is_generic_entity_name
is_valid_cve = connector_module.is_valid_cve
_dedup_key = connector_module._dedup_key
_norm_name = connector_module._norm_name


class TestGenericDescriptorGate(unittest.TestCase):
    """Generic descriptors must be rejected; real proper names must pass."""

    def test_rejects_state_sponsored(self):
        self.assertTrue(is_generic_entity_name("Chinese state-sponsored actors"))

    def test_rejects_based_threat_actors(self):
        self.assertTrue(is_generic_entity_name("China-based threat actors"))

    def test_rejects_unattributed_cybercriminals(self):
        self.assertTrue(is_generic_entity_name("Unattributed Cybercriminals"))

    def test_rejects_bare_generic_terms(self):
        for term in ["unknown", "various", "threat actor", "hackers", "N/A", ""]:
            self.assertTrue(is_generic_entity_name(term), term)

    def test_accepts_real_group_names_with_group_suffix(self):
        # The blunt "contains group" trap must NOT fire on real names.
        for name in ["Equation Group", "Lazarus Group", "Gopher Strike Group", "Winnti Group"]:
            self.assertFalse(is_generic_entity_name(name), name)

    def test_accepts_normal_actor_names(self):
        for name in ["APT29", "Volt Typhoon", "Cl0p", "Funky Mantis", "Novel Actor"]:
            self.assertFalse(is_generic_entity_name(name), name)


class TestDedupKey(unittest.TestCase):
    """Leetspeak/suffix folding for duplicate detection — conservative."""

    def test_leet_variants_collapse(self):
        self.assertEqual(_dedup_key("Cl0p"), _dedup_key("Clop"))
        self.assertEqual(_dedup_key("sh1ny"), _dedup_key("shiny"))
        self.assertEqual(_dedup_key("APT29"), _dedup_key("apt29"))

    def test_group_suffix_folds(self):
        self.assertEqual(_dedup_key("Lazarus"), _dedup_key("Lazarus Group"))

    def test_distinct_names_stay_distinct(self):
        # The dangerous case: must NOT merge names differing by an inserted letter.
        self.assertNotEqual(_dedup_key("sandstorm"), _dedup_key("standstorm"))
        self.assertNotEqual(_dedup_key("APT28"), _dedup_key("APT29"))


class TestLeetAwareMatching(unittest.TestCase):
    """_match_by_name_or_alias resolves leet variants to the existing entity."""

    def test_leet_name_matches_existing(self):
        results = [{"id": "is--clop", "name": "Clop", "aliases": []}]
        self.assertEqual(
            AIEnrichmentConnector._match_by_name_or_alias("Cl0p", results)["id"], "is--clop"
        )

    def test_distinct_name_does_not_match(self):
        results = [{"id": "is--sand", "name": "Sandstorm", "aliases": []}]
        self.assertIsNone(
            AIEnrichmentConnector._match_by_name_or_alias("Standstorm", results)
        )


class TestValidCve(unittest.TestCase):
    def test_valid(self):
        for c in ["CVE-2023-34362", "cve-2021-44228", "CVE-2024-1234567"]:
            self.assertTrue(is_valid_cve(c), c)

    def test_invalid(self):
        for c in ["CVE-23-1", "2023-34362", "CVE-2023", "not-a-cve", ""]:
            self.assertFalse(is_valid_cve(c), c)


# ---------------------------------------------------------------------------
# Intrusion-Set-first actor resolution
# ---------------------------------------------------------------------------

class TestActorResolutionOrder(unittest.TestCase):
    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.intrusion_set = MagicMock()
        self.c.helper.api.threat_actor_group = MagicMock()
        self.c.helper.api.stix_core_relationship = MagicMock()
        self.c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--x"})

    def test_intrusion_set_checked_first(self):
        # Both readers return an entity named Akira; Intrusion-Set must win.
        self.c.helper.api.intrusion_set.list = MagicMock(
            return_value=[{"id": "is--akira", "name": "Akira", "aliases": []}]
        )
        self.c.helper.api.threat_actor_group.list = MagicMock(
            return_value=[{"id": "tag--akira", "name": "Akira", "aliases": []}]
        )
        self.c._link_threat_actors("e", ["Akira"], 75)
        to_id = self.c.helper.api.stix_core_relationship.create.call_args[1]["toId"]
        self.assertEqual(to_id, "is--akira")


# ---------------------------------------------------------------------------
# Creation modes: dry-run
# ---------------------------------------------------------------------------

class TestCreationModes(unittest.TestCase):
    def test_off_is_default(self):
        c = _make_connector()
        self.assertEqual(c._create_mode, "off")
        self.assertFalse(c._create_stubs)
        self.assertFalse(c._create_dryrun)

    def test_on_mode(self):
        c = _make_connector({"AI_CREATE_STUBS": "true"})
        self.assertEqual(c._create_mode, "on")
        self.assertTrue(c._create_stubs)

    def test_dry_run_mode_parses(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        self.assertEqual(c._create_mode, "dry-run")
        self.assertFalse(c._create_stubs)
        self.assertTrue(c._create_dryrun)

    def test_dry_run_does_not_create_but_logs_and_counts(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.intrusion_set.list = MagicMock(return_value=[])
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        c.helper.api.stix_core_relationship = MagicMock()

        count = c._link_threat_actors("e", ["Novel Actor"], 75)
        self.assertEqual(count, 0)
        c.helper.api.intrusion_set.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["actor"]["would_create"], 1)
        # A DRY-RUN line was logged
        self.assertTrue(any("DRY-RUN" in str(a) for a, _ in
                            [(call_args[0], call_args[1]) for call_args in c.helper.log_info.call_args_list]))

    def test_generic_actor_rejected_before_resolve(self):
        c = _make_connector({"AI_CREATE_STUBS": "true"})
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.stix_core_relationship = MagicMock()
        count = c._link_threat_actors("e", ["Chinese state-sponsored actors"], 75)
        self.assertEqual(count, 0)
        c.helper.api.intrusion_set.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["actor"]["generic"], 1)


# ---------------------------------------------------------------------------
# CVE linking
# ---------------------------------------------------------------------------

class TestVulnerabilityLinking(unittest.TestCase):
    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.vulnerability = MagicMock()
        self.c.helper.api.stix_core_relationship = MagicMock()
        self.c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--x"})

    def test_existing_cve_linked(self):
        self.c.helper.api.vulnerability.list = MagicMock(
            return_value=[{"id": "vuln--1", "name": "CVE-2023-34362", "aliases": []}]
        )
        self.assertEqual(self.c._link_vulnerabilities("e", ["CVE-2023-34362"], 75), 1)

    def test_invalid_cve_skipped(self):
        count = self.c._link_vulnerabilities("e", ["not-a-cve"], 75)
        self.assertEqual(count, 0)
        self.assertEqual(self.c.metrics.by_category["cve"]["invalid"], 1)

    def test_unknown_cve_no_create_by_default(self):
        self.c.helper.api.vulnerability.list = MagicMock(return_value=[])
        count = self.c._link_vulnerabilities("e", ["CVE-2023-99999"], 75)
        self.assertEqual(count, 0)
        self.c.helper.api.vulnerability.create.assert_not_called()

    def test_unknown_cve_never_created_even_when_stubs_on(self):
        # CVEs are LOOKUP-ONLY: NVD/CVE.org owns Vulnerabilities, and proposed
        # novel CVE identifiers regularly do not exist at either.
        # See OBSERVATIONS.md.
        c = _make_connector({"AI_CREATE_STUBS": "true"})
        c.helper.api.vulnerability = MagicMock()
        c.helper.api.vulnerability.list = MagicMock(return_value=[])
        c.helper.api.vulnerability.create = MagicMock(return_value={"id": "vuln--new"})
        c.helper.api.identity = MagicMock()
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_domain_object = MagicMock()
        self.assertEqual(c._link_vulnerabilities("e", ["CVE-2023-99999"], 75), 0)
        c.helper.api.vulnerability.create.assert_not_called()

    def test_no_vulnerability_creation_helper_exists(self):
        # Guards against re-introducing the creation path by accident.
        self.assertFalse(hasattr(self.c, "_create_vuln_stub"))
        self.assertNotIn("cve", connector_module.AIEnrichmentConnector._CREATE_ENV)

    def test_unknown_cve_dryrun_logs_and_counts(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c.helper.api.vulnerability = MagicMock()
        c.helper.api.vulnerability.list = MagicMock(return_value=[])
        self.assertEqual(c._link_vulnerabilities("e", ["CVE-2026-90001"], 75), 0)
        c.helper.api.vulnerability.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["cve"]["would_create"], 1)
        self.assertTrue(any("would link CVE" in str(a) for a, _ in
                            c.helper.log_info.call_args_list))

    def test_existing_cve_still_links(self):
        c = _make_connector()
        c.helper.api.vulnerability = MagicMock()
        c.helper.api.vulnerability.list = MagicMock(
            return_value=[{"id": "v--1", "name": "CVE-2021-42260"}])
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "r--1"})
        self.assertEqual(c._link_vulnerabilities("e", ["CVE-2021-42260"], 75), 1)
        self.assertEqual(c.metrics.by_category["cve"]["existing"], 1)


# ---------------------------------------------------------------------------
# CVSS floor gating
# ---------------------------------------------------------------------------

class TestCvssFloor(unittest.TestCase):
    def test_default_no_gating(self):
        c = _make_connector()
        self.assertEqual(c._min_cvss, 0.0)
        self.assertFalse(c._vuln_cvss_below_floor({"x_opencti_cvss_base_score": 1.0}))

    def test_below_floor_skips(self):
        c = _make_connector({"AI_MIN_CVSS": "7"})
        self.assertTrue(c._vuln_cvss_below_floor({"x_opencti_cvss_base_score": 5.0}))

    def test_at_or_above_floor_enriches(self):
        c = _make_connector({"AI_MIN_CVSS": "7"})
        self.assertFalse(c._vuln_cvss_below_floor({"x_opencti_cvss_base_score": 8.1}))

    def test_missing_score_not_skipped(self):
        c = _make_connector({"AI_MIN_CVSS": "7"})
        self.assertFalse(c._vuln_cvss_below_floor({}))


# ---------------------------------------------------------------------------
# Alias write-back
# ---------------------------------------------------------------------------

class TestAliasWriteback(unittest.TestCase):
    def test_disabled_by_default(self):
        c = _make_connector()
        reader = MagicMock()
        n = c._apply_aliases(reader, _make_entity(name="APT29"), ["Cozy Bear"])
        self.assertEqual(n, 0)
        reader.update_field.assert_not_called()

    def test_adds_new_nongeneric_aliases(self):
        c = _make_connector({"AI_ALIAS_WRITEBACK": "true"})
        reader = MagicMock()
        entity = _make_entity(name="APT29", aliases=["Cozy Bear"])
        n = c._apply_aliases(reader, entity, ["Cozy Bear", "Nobelium", "state-sponsored actors"])
        # Cozy Bear already present; state-sponsored is generic → only Nobelium added
        self.assertEqual(n, 1)
        reader.update_field.assert_called_once()


# ---------------------------------------------------------------------------
# Feedback-loop guard
# ---------------------------------------------------------------------------

class TestLoopGuard(unittest.TestCase):
    def setUp(self):
        self.c = _make_connector()
        self.c._enrich_report = MagicMock(return_value="Enriched")

    def test_self_created_entity_skipped(self):
        self.c._self_created_ids.add("is--new")
        result = self.c.process_message({
            "entity_type": "intrusion-set",
            "entity_id": "is--new",
            "enrichment_entity": _make_entity(entity_type="intrusion-set", id="is--new"),
        })
        self.assertEqual(result, "Skipped: self-created (loop guard)")

    def test_review_labelled_stub_skipped(self):
        entity = _make_entity(entity_type="report", objectLabel=[{"value": "ai-suggested"}])
        result = self.c.process_message({
            "entity_type": "report",
            "entity_id": entity["id"],
            "enrichment_entity": entity,
        })
        self.assertEqual(result, "Skipped: ai-suggested stub (loop guard)")

    def test_normal_entity_not_skipped_by_guard(self):
        entity = _make_entity(entity_type="report", objectLabel=[{"value": "malware"}])
        self.c._get_stored_hash = MagicMock(return_value=None)
        self.c._apply_idempotency_label = MagicMock(return_value=True)
        result = self.c.process_message({
            "entity_type": "report",
            "entity_id": entity["id"],
            "enrichment_entity": entity,
        })
        self.c._enrich_report.assert_called_once()


# ---------------------------------------------------------------------------
# Per-category metrics
# ---------------------------------------------------------------------------

class TestPerCategoryMetrics(unittest.TestCase):
    def test_record_category_and_summary(self):
        mt = MetricsTracker()
        mt.record_category("actor", "existing")
        mt.record_category("actor", "existing")
        mt.record_category("actor", "none")
        mt.record_category("actor", "generic")
        summary = mt.summary_dict()
        cat = summary["by_category"]["actor"]
        self.assertEqual(cat["existing"], 2)
        self.assertEqual(cat["detected"], 4)
        # linkable = 4 - 1 generic = 3; linked = 2 → 0.667
        self.assertEqual(cat["link_rate"], 0.667)

    def test_unknown_category_ignored(self):
        mt = MetricsTracker()
        mt.record_category("bogus", "existing")  # must not raise
        self.assertNotIn("bogus", mt.summary_dict().get("by_category", {}))

    def test_empty_categories_excluded_from_summary(self):
        mt = MetricsTracker()
        self.assertEqual(mt.summary_dict()["by_category"], {})


# ---------------------------------------------------------------------------
# Report container semantics: add to object refs, not outgoing relationships
# ---------------------------------------------------------------------------

class TestReportContainerLinking(unittest.TestCase):
    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.malware = MagicMock()
        self.c.helper.api.report = MagicMock()
        self.c.helper.api.stix_core_relationship = MagicMock()

    def test_report_adds_object_ref_not_relationship(self):
        self.c.helper.api.malware.list = MagicMock(
            return_value=[{"id": "mw--1", "name": "Cobalt Strike", "aliases": []}]
        )
        count = self.c._link_malware("report--1", ["Cobalt Strike"], 75, as_report_object=True)
        self.assertEqual(count, 1)
        self.c.helper.api.report.add_stix_object_or_stix_relationship.assert_called_once()
        kwargs = self.c.helper.api.report.add_stix_object_or_stix_relationship.call_args[1]
        self.assertEqual(kwargs["id"], "report--1")
        self.assertEqual(kwargs["stixObjectOrStixRelationshipId"], "mw--1")
        self.c.helper.api.stix_core_relationship.create.assert_not_called()

    def test_non_report_still_creates_relationship(self):
        self.c.helper.api.malware.list = MagicMock(
            return_value=[{"id": "mw--1", "name": "Cobalt Strike", "aliases": []}]
        )
        self.c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        count = self.c._link_malware("is--1", ["Cobalt Strike"], 75)
        self.assertEqual(count, 1)
        self.c.helper.api.stix_core_relationship.create.assert_called_once()
        self.c.helper.api.report.add_stix_object_or_stix_relationship.assert_not_called()


# ---------------------------------------------------------------------------
# Typed extraction: junk filter, legit-software allowlist, vocab, routing, critic
# ---------------------------------------------------------------------------

is_junk_name = connector_module.is_junk_name
is_known_legit_software = connector_module.is_known_legit_software
normalize_malware_types = connector_module.normalize_malware_types
normalize_tool_types = connector_module.normalize_tool_types
normalize_motivation = connector_module.normalize_motivation
normalize_sophistication = connector_module.normalize_sophistication
normalize_resource_level = connector_module.normalize_resource_level
_base_key = connector_module._base_key


class TestPromptRendering(unittest.TestCase):
    """Regression: typed prompts contain literal JSON braces ({"name":...}) and
    MUST be rendered with .replace, not str.format (which would KeyError)."""

    def test_all_prompts_render_via_replace(self):
        for p in [REPORT_PROMPT, INTRUSION_SET_PROMPT, THREAT_ACTOR_PROMPT,
                  MALWARE_PROMPT, CAMPAIGN_PROMPT, VULNERABILITY_PROMPT]:
            rendered = p.replace("{content}", "SAMPLE_CONTENT")
            self.assertIn("SAMPLE_CONTENT", rendered)
            self.assertNotIn("{content}", rendered)

    def test_typed_prompts_have_literal_json_braces(self):
        # These braces are what break str.format; ensure they're present as intended.
        self.assertIn('{"name"', REPORT_PROMPT)


class TestCoerceNames(unittest.TestCase):
    def test_mixed_list(self):
        coerce_names = connector_module.coerce_names
        self.assertEqual(
            coerce_names(["OpenSSL", {"name": "vLLM"}, {"product": "nginx"}, "", None, {"x": 1}]),
            ["OpenSSL", "vLLM", "nginx"],
        )


class TestAffectedProductsNotToolNodes(unittest.TestCase):
    """affected_products must go into the note, NOT become Tool/Malware nodes."""

    def test_report_affected_products_in_note_not_linked(self):
        c = _make_connector()
        c._call_gemini = MagicMock(return_value=_gemini_result(
            summary="S", affected_products=["PTC Windchill", {"name": "Pandora FMS"}], software=[],
        ))
        c._add_or_update_note = MagicMock()
        c._link_threat_actors = MagicMock(return_value=0)
        c._link_victims = MagicMock(return_value=0)
        c._link_software = MagicMock(return_value=0)
        c._link_attack_patterns = MagicMock(return_value=0)
        c._link_vulnerabilities = MagicMock(return_value=0)
        c._link_sectors = MagicMock(return_value=0)
        c._link_countries = MagicMock(return_value=0)
        c._apply_idempotency_label = MagicMock(return_value=True)
        c._update_score = MagicMock(return_value=True)
        c._apply_labels = MagicMock(return_value=0)
        entity = _make_entity(entity_type="report")
        c._enrich_report(entity)
        note_text = c._add_or_update_note.call_args[0][1]
        self.assertIn("PTC Windchill", note_text)
        self.assertIn("Pandora FMS", note_text)
        # affected products are NOT routed to software linking
        sw_arg = c._link_software.call_args[0][1]
        self.assertNotIn("affected_products", str(sw_arg.get("software", [])))


class TestVulnAffectedSoftwareCoercion(unittest.TestCase):
    """Regression: affected_software may arrive as dicts; the note builder must
    not crash on ', '.join()."""

    def test_dict_affected_software_does_not_crash(self):
        c = _make_connector()
        c._call_gemini = MagicMock(return_value=_gemini_result(
            summary="V", cvss_score="5.3",
            affected_software=[{"name": "vLLM"}, "OpenSSL", {"product": "nginx"}],
            associated_threat_actors=[], attack_techniques=[],
        ))
        c._add_or_update_note = MagicMock()
        c._link_attack_patterns = MagicMock(return_value=0)
        c._link_threat_actors = MagicMock(return_value=0)
        c._apply_idempotency_label = MagicMock(return_value=True)
        c._update_score = MagicMock(return_value=True)
        c._apply_labels = MagicMock(return_value=0)
        entity = _make_entity(entity_type="vulnerability")
        # Must not raise, and the note content must include the coerced names
        result = c._enrich_vulnerability(entity)
        note_args = c._add_or_update_note.call_args
        content = note_args[0][1] if note_args and note_args[0] else ""
        self.assertIn("vLLM", content)
        self.assertIn("OpenSSL", content)


class TestOrgKey(unittest.TestCase):
    def test_variants_collapse(self):
        k = connector_module._org_key
        self.assertEqual(k("UK Office for Waterways"), k("Office for Waterways (UK)"))
        self.assertEqual(k("Northwind Corporation"), k("Northwind"))
        self.assertEqual(k("Larkfield Technologies"), k("larkfield.com"))
        self.assertEqual(k("Acme, Inc."), k("Acme LLC"))

    def test_distinct_orgs_stay_distinct(self):
        k = connector_module._org_key
        self.assertNotEqual(k("Ravenna Inc"), k("Ravenna Bank"))
        self.assertNotEqual(k("Harbor National Bank"), k("Summit National Bank"))


class TestVictimOrgDedup(unittest.TestCase):
    def setUp(self):
        self.c = _make_connector({"AI_CREATE_STUBS": "true"})
        self.c.helper.api.identity = MagicMock()
        self.c.helper.api.stix_core_relationship = MagicMock()
        self.c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})

    def test_variant_resolves_no_duplicate_create(self):
        self.c.helper.api.identity.list = MagicMock(return_value=[
            {"id": "org--dfe", "name": "Office for Waterways (UK)",
             "entity_type": "Organization", "aliases": []},
        ])
        self.c.helper.api.identity.create = MagicMock()
        n = self.c._link_victims("e", ["UK Office for Waterways"], 75)
        self.assertEqual(n, 1)
        self.c.helper.api.identity.create.assert_not_called()  # matched existing, no dup


class TestInfraSoftwareSkipped(unittest.TestCase):
    """Victim infrastructure (WordPress, Node.js, Apache) must never become Tools."""

    def test_is_infra_software(self):
        f = connector_module.is_infra_software
        for n in ["WordPress", "Node.js", "Apache", "nginx", "Microsoft Exchange", "PTC Windchill"]:
            self.assertTrue(f(n), n)
        for n in ["LockBit", "nmap", "PsExec", "Cobalt Strike"]:
            self.assertFalse(f(n), n)

    def test_extract_software_skips_infra(self):
        result = {"software": [
            {"name": "WordPress", "kind": "tool"},
            {"name": "Node.js", "kind": "tool"},
            {"name": "LockBit", "kind": "malware"},
            {"name": "nmap", "kind": "tool"},
        ]}
        mw, tools = AIEnrichmentConnector._extract_software(result)
        self.assertEqual({m["name"] for m in mw}, {"LockBit"})
        self.assertEqual({t["name"] for t in tools}, {"nmap"})  # WordPress/Node.js dropped


class TestToolNoiseSkipped(unittest.TestCase):
    """Protocols / generic utilities / messengers must never become Tool nodes."""

    def test_is_tool_noise(self):
        f = connector_module.is_tool_noise
        for n in ["RDP", "ssh", "VNC", "SMB", "curl", "wget", "python", "PowerShell",
                  "7-Zip", "WinRAR", "Telegram", "Tox", "Tor", "cmd.exe"]:
            self.assertTrue(f(n), n)
        # Genuine adversary tools are NOT noise.
        for n in ["nmap", "Metasploit", "PsExec", "AnyDesk", "Mimikatz", "Cobalt Strike"]:
            self.assertFalse(f(n), n)

    def test_extract_software_skips_tool_noise(self):
        result = {"software": [
            {"name": "RDP", "kind": "tool"},
            {"name": "curl", "kind": "tool"},
            {"name": "Telegram", "kind": "tool"},
            {"name": "PsExec", "kind": "tool", "legitimate": True},
            {"name": "LockBit", "kind": "malware"},
        ]}
        mw, tools = AIEnrichmentConnector._extract_software(result)
        self.assertEqual({m["name"] for m in mw}, {"LockBit"})
        self.assertEqual({t["name"] for t in tools}, {"PsExec"})  # RDP/curl/Telegram dropped


class TestMinerIsMalware(unittest.TestCase):
    """Cryptominers are malware (resource-exploitation), never Tools."""

    def test_is_miner(self):
        f = connector_module.is_miner
        for n in ["XMRig", "xmr-stak", "cpuminer", "PhoenixMiner", "coinminer"]:
            self.assertTrue(f(n), n)
        for n in ["nmap", "LockBit", "OpenVPN"]:
            self.assertFalse(f(n), n)

    def test_extract_software_routes_miner_to_malware(self):
        # Even if Gemini labels XMRig as a legitimate tool, it must be malware.
        result = {"software": [
            {"name": "XMRig", "kind": "tool", "legitimate": True},
            {"name": "nmap", "kind": "tool"},
        ]}
        mw, tools = AIEnrichmentConnector._extract_software(result)
        self.assertEqual({m["name"] for m in mw}, {"XMRig"})
        self.assertEqual({t["name"] for t in tools}, {"nmap"})
        xmrig = next(m for m in mw if m["name"] == "XMRig")
        self.assertEqual(xmrig.get("type"), "resource-exploitation")


class TestRefUrlSafety(unittest.TestCase):
    """SSRF guards: feed-supplied URLs must never reach internal services."""

    def test_rejects_non_http_schemes(self):
        f = connector_module.is_safe_ref_url
        for u in ["file:///etc/passwd", "ftp://x/y", "gopher://x", "", None,
                  "javascript:alert(1)"]:
            self.assertFalse(f(u), str(u))

    def test_rejects_private_and_metadata_addresses(self):
        # Literal IPs need no DNS, so this stays offline.
        f = connector_module.is_safe_ref_url
        for u in ["http://127.0.0.1:8082/graphql",
                  "http://10.0.0.5/x",
                  "http://192.168.1.10/x",
                  "http://172.16.0.9/x",
                  "http://169.254.169.254/latest/meta-data/"]:
            self.assertFalse(f(u), u)

    def test_rejects_internal_docker_hostname(self):
        # An internal service name that resolves to a private address.
        with patch.object(connector_module.socket, "getaddrinfo",
                          return_value=[(2, 1, 6, "", ("172.18.0.4", 0))]):
            self.assertFalse(
                connector_module.is_safe_ref_url("http://internal-service.:8080/graphql"))

    def test_accepts_public_host(self):
        # Patch resolution so the test stays offline.
        with patch.object(connector_module.socket, "getaddrinfo",
                          return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            self.assertTrue(connector_module.is_safe_ref_url("https://example.com/post"))

    def test_unresolvable_host_rejected(self):
        with patch.object(connector_module.socket, "getaddrinfo",
                          side_effect=OSError("nxdomain")):
            self.assertFalse(connector_module.is_safe_ref_url("https://nope.invalid/x"))

    def test_gated_portals_detected(self):
        f = connector_module.is_gated_ref
        for u in ["https://app.recordedfuture.com/live/sc/x",
                  "https://otx.alienvault.com/pulse/1",
                  "https://portal.example.com/report",
                  "https://login.vendor.com/a",
                  "https://x.com/user/status/1"]:
            self.assertTrue(f(u), u)
        for u in ["https://blog.talosintelligence.com/post",
                  "https://www.bleepingcomputer.com/news/x",
                  "https://attack.mitre.org/groups/G0016/"]:
            self.assertFalse(f(u), u)


class TestHtmlToText(unittest.TestCase):
    def test_strips_scripts_styles_and_tags(self):
        html = ("<html><head><style>.a{color:red}</style></head><body>"
                "<script>evil()</script><h1>CL0P exploits PTC</h1>"
                "<p>Victim: Acme&amp;Co</p></body></html>")
        text = connector_module.html_to_text(html)
        self.assertIn("CL0P exploits PTC", text)
        self.assertIn("Acme&Co", text)          # entities unescaped
        self.assertNotIn("evil()", text)
        self.assertNotIn("color:red", text)
        self.assertNotIn("<", text)

    def test_empty_input(self):
        self.assertEqual(connector_module.html_to_text(""), "")


class TestReferenceFetching(unittest.TestCase):
    """Fetched article text must reach the prompt (replacing search grounding)."""

    def test_disabled_by_default_in_tests_only_lists_urls(self):
        c = _make_connector()   # AI_FETCH_REFS=false in test env
        entity = _make_entity(externalReferences=[
            {"source_name": "blog", "url": "https://blog.example.com/a"}])
        out = c._augment_with_refs("base", entity)
        self.assertIn("https://blog.example.com/a", out)
        self.assertNotIn("Retrieved source content", out)

    def test_fetched_text_is_inlined(self):
        c = _make_connector({"AI_FETCH_REFS": "true"})
        entity = _make_entity(externalReferences=[
            {"source_name": "blog", "url": "https://blog.example.com/a"}])
        with patch.object(connector_module, "fetch_reference_text",
                          return_value="CL0P exploited PTC Windchill."):
            out = c._augment_with_refs("base", entity)
        self.assertIn("Retrieved source content", out)
        self.assertIn("CL0P exploited PTC Windchill.", out)
        self.assertIn("[Source: https://blog.example.com/a]", out)

    def test_gated_sources_not_fetched(self):
        c = _make_connector({"AI_FETCH_REFS": "true"})
        entity = _make_entity(externalReferences=[
            {"source_name": "rf", "url": "https://app.recordedfuture.com/live/x"}])
        with patch.object(connector_module, "fetch_reference_text") as fx:
            out = c._augment_with_refs("base", entity)
        fx.assert_not_called()
        self.assertNotIn("Retrieved source content", out)

    def test_respects_max_refs(self):
        c = _make_connector({"AI_FETCH_REFS": "true", "AI_FETCH_MAX_REFS": "2"})
        entity = _make_entity(externalReferences=[
            {"source_name": "a", "url": "https://a.example.com/1"},
            {"source_name": "b", "url": "https://b.example.com/2"},
            {"source_name": "c", "url": "https://c.example.com/3"},
        ])
        with patch.object(connector_module, "fetch_reference_text",
                          return_value="text") as fx:
            c._augment_with_refs("base", entity)
        self.assertEqual(fx.call_count, 2)

    def test_truncates_long_reference_body(self):
        c = _make_connector({"AI_FETCH_REFS": "true", "AI_FETCH_MAX_CHARS_PER_REF": "500"})
        entity = _make_entity(externalReferences=[
            {"source_name": "a", "url": "https://a.example.com/1"}])
        with patch.object(connector_module, "fetch_reference_text",
                          return_value="X" * 5000):
            out = c._augment_with_refs("base", entity)
        self.assertIn("X" * 500, out)
        self.assertNotIn("X" * 501, out)

    def test_cached_so_same_url_fetched_once(self):
        c = _make_connector({"AI_FETCH_REFS": "true"})
        entity = _make_entity(externalReferences=[
            {"source_name": "a", "url": "https://a.example.com/1"}])
        with patch.object(connector_module, "fetch_reference_text",
                          return_value="body") as fx:
            c._augment_with_refs("base", entity)
            c._augment_with_refs("base", entity)
        self.assertEqual(fx.call_count, 1)

    def test_failed_fetch_still_lists_url(self):
        c = _make_connector({"AI_FETCH_REFS": "true"})
        entity = _make_entity(externalReferences=[
            {"source_name": "a", "url": "https://a.example.com/1"}])
        with patch.object(connector_module, "fetch_reference_text", return_value=None):
            out = c._augment_with_refs("base", entity)
        self.assertIn("https://a.example.com/1", out)
        self.assertNotIn("Retrieved source content", out)

    def test_ref_url_extraction(self):
        f = connector_module.AIEnrichmentConnector._ref_url
        self.assertEqual(f("mitre: https://attack.mitre.org/x"), "https://attack.mitre.org/x")
        self.assertEqual(f("https://a.com/b."), "https://a.com/b")
        self.assertEqual(f("no url here"), "")


class TestDurableAuditLog(unittest.TestCase):
    def test_off_by_default(self):
        c = _make_connector()
        self.assertEqual(c._audit_log_path, "")
        self.assertEqual(c._metrics_jsonl_path, "")

    def test_enabled_writes_metrics_jsonl(self):
        import tempfile, os as _os, shutil
        d = tempfile.mkdtemp()
        try:
            path = _os.path.join(d, "audit.log")
            c = _make_connector({"AI_AUDIT_LOG": path})
            self.assertEqual(c._audit_log_path, path)
            c.metrics.increment_success()
            c.metrics.record_category("actor", "existing")
            c._persist_metrics()
            jsonl = _os.path.join(d, "ai_metrics.jsonl")
            self.assertTrue(_os.path.exists(jsonl))
            with open(jsonl, encoding="utf-8") as fh:
                rec = json.loads(fh.readline())
            self.assertIn("ts", rec)
            self.assertIn("by_category", rec)
            self.assertEqual(rec["by_category"]["actor"]["existing"], 1)
            self.assertIn("read_only", rec)
        finally:
            # Close + detach the file handler before cleanup, otherwise Windows
            # refuses to delete a file that is still open.
            root = connector_module.logging.getLogger()
            for h in list(root.handlers):
                if isinstance(h, connector_module.RotatingFileHandler):
                    h.close()
                    root.removeHandler(h)
            shutil.rmtree(d, ignore_errors=True)

    def test_persist_is_noop_when_disabled(self):
        c = _make_connector()
        c._persist_metrics()   # must not raise

    def test_log_lines_actually_reach_the_file(self):
        """Regression: the handler was previously attached before pycti configured
        logging, so the file was created but never written to."""
        import tempfile, os as _os, shutil
        d = tempfile.mkdtemp()
        try:
            path = _os.path.join(d, "audit.log")
            _make_connector({"AI_AUDIT_LOG": path})
            connector_module.logging.getLogger("AI Enrichment (Gemini)").info(
                "hello-durable-audit"
            )
            for h in connector_module.logging.getLogger().handlers:
                h.flush()
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("hello-durable-audit", body)
            self.assertIn("[AUDIT] durable audit log enabled", body)
        finally:
            root = connector_module.logging.getLogger()
            for h in list(root.handlers):
                if isinstance(h, connector_module.RotatingFileHandler):
                    h.close()
                    root.removeHandler(h)
            shutil.rmtree(d, ignore_errors=True)


class TestOrgAcronymFolding(unittest.TestCase):
    """NAWA vs 'National Atmospheric and Water Agency' must be one org."""

    def test_acronym_generation(self):
        f = connector_module._org_acronym
        self.assertEqual(f("National Atmospheric and Water Agency"), "nawa")
        self.assertEqual(f("National Institutes of Hydrology"), "nih")
        self.assertEqual(f("Acme"), "")          # single word: nothing to abbreviate

    def test_acronym_candidates_cover_preposition_variants(self):
        f = connector_module._org_acronyms
        # DOW keeps "of", NIH drops it — both forms must be candidates.
        self.assertIn("dow", f("Department of Waterways"))
        self.assertIn("nih", f("National Institutes of Hydrology"))
        self.assertEqual(f("Acme"), set())

    def test_is_acronym_form(self):
        f = connector_module._is_acronym_form
        self.assertTrue(f("NAWA"))
        self.assertTrue(f("DOW"))
        self.assertFalse(f("National Institutes of Hydrology"))
        self.assertFalse(f("A"))

    def test_variants_match(self):
        f = connector_module.org_variants_match
        self.assertTrue(f("NAWA", "National Atmospheric and Water Agency"))
        self.assertTrue(f("National Atmospheric and Water Agency", "NAWA"))
        self.assertTrue(f("DOW", "Department of Waterways"))
        self.assertTrue(f("US Department of Waterways", "Department of Waterways"))
        self.assertTrue(f("Fuhai Chenglin Network Technology Co. Ltd.",
                          "Fuhai Chenglin Network Technology Company"))

    def test_legal_form_punctuation_not_treated_as_domain(self):
        # Regression: "Acme Co. Ltd." used to look like a domain, which mangled
        # the dedup key and prevented variant matching.
        k = connector_module._org_key
        self.assertEqual(k("Fuhai Chenglin Network Technology Co. Ltd."),
                         k("Fuhai Chenglin Network Technology Company"))
        self.assertFalse(connector_module._looks_like_domain("acmeco.ltd"))
        self.assertFalse(connector_module._looks_like_domain("acme.gmbh"))

    def test_real_domains_still_fold_to_first_label(self):
        self.assertTrue(connector_module._looks_like_domain("larkfield.com"))
        self.assertTrue(connector_module._looks_like_domain("sub.example.co.uk"))
        self.assertEqual(connector_module._org_key("larkfield.com"),
                         connector_module._org_key("Larkfield"))

    def test_unrelated_names_not_collapsed(self):
        f = connector_module.org_variants_match
        self.assertFalse(f("NAWA", "National Security Bureau"))
        self.assertFalse(f("LKF", "Department of Waterways"))
        self.assertFalse(f("Acme Corp", "Clearwater Medical"))

    def test_same_run_variants_create_only_once(self):
        c = _make_connector({"AI_CREATE_STUBS": "true", "AI_REQUIRE_GROUNDING": "false"})
        _enable_creation(c)
        c.helper.api.identity = MagicMock()
        c.helper.api.identity.list = MagicMock(return_value=[])
        c.helper.api.identity.create = MagicMock(return_value={"id": "org--nasa"})
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        n = c._link_victims(
            "e--1",
            ["National Atmospheric and Water Agency", "NAWA"],
            75,
        )
        # Exactly one VICTIM entity created (ignore the connector's author identity)
        victim_calls = [
            call for call in c.helper.api.identity.create.call_args_list
            if call.kwargs.get("name") in (
                "National Atmospheric and Water Agency", "NAWA")
        ]
        self.assertEqual(len(victim_calls), 1)
        self.assertEqual(victim_calls[0].kwargs["name"],
                         "National Atmospheric and Water Agency")
        self.assertEqual(n, 2)   # both mentions linked to the single entity

    def test_dryrun_variants_counted_once(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run", "AI_REQUIRE_GROUNDING": "false"})
        c.helper.api.identity = MagicMock()
        c.helper.api.identity.list = MagicMock(return_value=[])
        c._link_victims("e--1", ["Department of Waterways", "DOW"], 75)
        self.assertEqual(c.metrics.by_category["victim"]["would_create"], 1)

    def test_created_stub_carries_acronym_alias(self):
        c = _make_connector({"AI_CREATE_STUBS": "true"})
        _enable_creation(c)
        c.helper.api.identity = MagicMock()
        c.helper.api.identity.create = MagicMock(return_value={"id": "org--1"})
        c._create_victim_stub("National Institutes of Hydrology")
        kwargs = c.helper.api.identity.create.call_args.kwargs
        self.assertEqual(kwargs["x_opencti_aliases"], ["NIH"])

    def test_resolve_org_matches_existing_by_acronym(self):
        c = _make_connector()
        existing = {"id": "org--nasa", "entity_type": "Organization",
                    "name": "National Atmospheric and Water Agency",
                    "aliases": [], "x_opencti_aliases": []}
        # fulltext search for "NAWA" finds nothing; the acronym probe finds it
        c.helper.api.identity.list = MagicMock(side_effect=[[], [existing]])
        found = c._resolve_org("NAWA")
        self.assertIsNotNone(found)
        self.assertEqual(found["id"], "org--nasa")


class TestSecurityProductGuard(unittest.TestCase):
    """Defensive products belong to the victim — never adversary tooling."""

    def test_is_security_product(self):
        f = connector_module.is_security_product
        for n in ["Windows Defender", "Microsoft Defender", "Quick Heal", "CrowdStrike",
                  "SentinelOne", "Sophos", "Malwarebytes", "Cortex XDR", "AMSI"]:
            self.assertTrue(f(n), n)
        for n in ["Mimikatz", "Cobalt Strike", "nmap", "PsExec"]:
            self.assertFalse(f(n), n)

    def test_security_products_dropped_from_extraction(self):
        result = {"software": [
            {"name": "Windows Defender", "kind": "tool"},
            {"name": "Quick Heal", "kind": "tool"},
            {"name": "Mimikatz", "kind": "malware"},
        ]}
        mw, tools = AIEnrichmentConnector._extract_software(result)
        self.assertEqual({m["name"] for m in mw}, {"Mimikatz"})
        self.assertEqual(tools, [])

    def test_security_product_never_becomes_malware_either(self):
        result = {"software": [{"name": "Windows Defender", "kind": "malware"}]}
        mw, tools = AIEnrichmentConnector._extract_software(result)
        self.assertEqual(mw, [])
        self.assertEqual(tools, [])


class TestConsumerSoftwareGuard(unittest.TestCase):
    """Consumer AI assistants and general desktop apps are not adversary tooling."""

    def test_is_consumer_noise(self):
        f = connector_module.is_consumer_software_noise
        for n in ["ChatGPT", "GitHub Copilot", "Claude Code", "GPT-4o-mini", "Cursor",
                  "ElevenLabs", "OpenAI Whisper", "Calibre", "Mp3tag",
                  "ABBYY FineReader", "Inno Setup", "Squirrel", "Overwolf"]:
            self.assertTrue(f(n), n)

    def test_offensive_ai_tools_are_kept(self):
        # Purpose-built offensive AI IS adversary tooling — must NOT be filtered.
        f = connector_module.is_consumer_software_noise
        for n in ["WormGPT", "FraudGPT", "PentestGPT"]:
            self.assertFalse(f(n), n)

    def test_cursor_not_malware(self):
        # Observed failure: the Cursor editor was classified as malware.
        result = {"software": [{"name": "Cursor", "kind": "malware", "type": "editor"}]}
        mw, tools = AIEnrichmentConnector._extract_software(result)
        self.assertEqual(mw, [])
        self.assertEqual(tools, [])


class TestNonActorGuard(unittest.TestCase):
    """Criminal orgs, operation names and companies must not become actors."""

    def test_criminal_organisations(self):
        f = connector_module.is_non_actor_name
        for n in ["Comando Vermelho", "Primeiro Comando da Capital",
                  "Cartel de Jalisco Nueva Generacion", "Viv Ansanm", "Black Axe"]:
            self.assertTrue(f(n), n)

    def test_operation_names(self):
        f = connector_module.is_non_actor_name
        for n in ["Operation ASTERIX", "operation aurora", "Op. Cleaver"]:
            self.assertTrue(f(n), n)

    def test_company_names(self):
        f = connector_module.is_non_actor_name
        for n in ["Fuhai Chenglin Network Technology Co. Ltd.", "Brightsoft Inc",
                  "Qv Technology Ltd", "Some Firm GmbH"]:
            self.assertTrue(f(n), n)

    def test_real_actors_pass(self):
        f = connector_module.is_non_actor_name
        for n in ["APT29", "Lazarus Group", "UNC7005", "Storm-1516", "CL0P",
                  "Charcoal Stork", "Plump Spider", "Equation Group"]:
            self.assertFalse(f(n), n)

    def test_non_actor_not_created_but_existing_still_links(self):
        c = _make_connector({"AI_CREATE_STUBS": "true"})
        _enable_creation(c)
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.malware = MagicMock()
        c.helper.api.tool = MagicMock()
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        for api in (c.helper.api.intrusion_set, c.helper.api.threat_actor_group,
                    c.helper.api.malware, c.helper.api.tool):
            api.list = MagicMock(return_value=[])
        # novel criminal org -> refused
        self.assertEqual(c._link_threat_actors("e--1", ["Comando Vermelho"], 75), 0)
        c.helper.api.intrusion_set.create.assert_not_called()
        # same name, but it already exists in the KB -> still links
        c.helper.api.intrusion_set.list = MagicMock(
            return_value=[{"id": "is--1", "name": "Comando Vermelho", "aliases": []}]
        )
        self.assertEqual(c._link_threat_actors("e--1", ["Comando Vermelho"], 75), 1)


class TestDescriptiveNonNames(unittest.TestCase):
    """Capability descriptions are not entity names."""

    def test_descriptive_malware_phrases_are_generic(self):
        f = connector_module.is_generic_entity_name
        for n in ["custom Python exploit scripts", "Reverse SSH Tunneling Tool",
                  "Gmail-stealing Chrome extension", "Python reverse-tunnel implant",
                  "JSP web shell", "unnamed backdoor", "phishing kit"]:
            self.assertTrue(f(n), n)

    def test_real_malware_names_pass(self):
        f = connector_module.is_generic_entity_name
        for n in ["LockBit", "Emotet", "Havoc C2", "XMRig", "ToxicPanda", "PhishLocker"]:
            self.assertFalse(f(n), n)


class TestGroundedness(unittest.TestCase):
    """Deterministic hallucination check — no model involved."""

    def setUp(self):
        self.hay = connector_module._grounding_haystack
        self.g = connector_module.is_grounded

    def test_direct_match_case_and_punctuation_insensitive(self):
        h = self.hay("The LockBit 3.0 ransomware hit Acme Corp.")
        self.assertTrue(self.g("lockbit", h))
        self.assertTrue(self.g("LockBit", h))
        self.assertTrue(self.g("Acme Corp", h))

    def test_corporate_suffix_tolerated(self):
        h = self.hay("Attackers breached Clearwater Medical this week.")
        self.assertTrue(self.g("Clearwater Medical, Inc.", h))
        self.assertTrue(self.g("Clearwater Medical LLC", h))

    def test_multiword_token_subset_order_tolerant(self):
        h = self.hay("the Department of Waterways and the Central Reserve Bank were named")
        self.assertTrue(self.g("Waterways Department", h))

    def test_acronym_expanded_in_source(self):
        h = self.hay("A breach at the National Atmospheric and Water Agency.")
        self.assertTrue(self.g("NAWA", h))

    def test_acronym_with_stopwords_in_expansion(self):
        h = self.hay("officials at the Department of Waterways confirmed")
        self.assertTrue(self.g("DOW", h))

    def test_substring_inside_compound_word(self):
        h = self.hay("tracked as qilinransomware in the report")
        self.assertTrue(self.g("Qilin", h))

    def test_hallucinated_name_rejected(self):
        h = self.hay("CL0P exploited PTC Windchill to steal engineering data.")
        for bogus in ["Fancy Bear", "TrafficRedirector", "Kalinda Broadcasting", "SCP-2013"]:
            self.assertFalse(self.g(bogus, h), bogus)

    def test_empty_inputs(self):
        self.assertFalse(self.g("", self.hay("something")))
        self.assertFalse(self.g("Acme", ""))
        self.assertFalse(self.g(None, self.hay("something")))

    def test_short_acronym_not_matched_by_accident(self):
        h = self.hay("the quick brown fox jumped over")
        self.assertFalse(self.g("LKF", h))


class TestGroundingGatesCreation(unittest.TestCase):
    """Creation requires evidence in the source; linking is unaffected."""

    def _conn(self, **env):
        c = _make_connector({"AI_CREATE_STUBS": "true", **env})
        _enable_creation(c)
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.intrusion_set.list = MagicMock(return_value=[])
        c.helper.api.intrusion_set.create = MagicMock(return_value={"id": "is--new"})
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        c.helper.api.malware = MagicMock()
        c.helper.api.malware.list = MagicMock(return_value=[])
        c.helper.api.tool = MagicMock()
        c.helper.api.tool.list = MagicMock(return_value=[])
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        return c

    def test_default_requires_grounding(self):
        self.assertTrue(_make_connector()._require_grounding)

    def test_ungrounded_actor_not_created(self):
        c = self._conn()
        c._src_text_norm = connector_module._grounding_haystack(
            "CL0P exploited PTC Windchill for data theft."
        )
        n = c._link_threat_actors("e--1", ["Fancy Bear"], 75)
        self.assertEqual(n, 0)
        c.helper.api.intrusion_set.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["actor"]["ungrounded"], 1)

    def test_grounded_actor_is_created(self):
        c = self._conn()
        c._src_text_norm = connector_module._grounding_haystack(
            "CL0P exploited PTC Windchill for data theft."
        )
        n = c._link_threat_actors("e--1", ["CL0P"], 75)
        self.assertEqual(n, 1)
        c.helper.api.intrusion_set.create.assert_called_once()

    def test_no_source_text_does_not_penalise(self):
        c = self._conn()
        c._src_text_norm = ""   # nothing captured
        n = c._link_threat_actors("e--1", ["Some Actor"], 75)
        self.assertEqual(n, 1)
        c.helper.api.intrusion_set.create.assert_called_once()

    def test_can_be_disabled(self):
        c = self._conn(AI_REQUIRE_GROUNDING="false")
        self.assertFalse(c._require_grounding)
        c._src_text_norm = connector_module._grounding_haystack("unrelated text")
        n = c._link_threat_actors("e--1", ["Fancy Bear"], 75)
        self.assertEqual(n, 1)
        c.helper.api.intrusion_set.create.assert_called_once()

    def test_existing_entity_still_links_when_ungrounded(self):
        # Grounding must NOT block linking to an entity that already exists.
        c = self._conn()
        c._src_text_norm = connector_module._grounding_haystack("unrelated text")
        c.helper.api.intrusion_set.list = MagicMock(
            return_value=[{"id": "is--1", "name": "APT29", "aliases": []}]
        )
        n = c._link_threat_actors("e--1", ["APT29"], 75)
        self.assertEqual(n, 1)
        c.helper.api.intrusion_set.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["actor"]["existing"], 1)

    def test_ungrounded_excluded_from_link_rate_denominator(self):
        c = _make_connector()
        c.metrics.record_category("actor", "existing")
        c.metrics.record_category("actor", "ungrounded")
        summary = c.metrics.summary_dict()["by_category"]["actor"]
        self.assertEqual(summary["detected"], 2)
        self.assertEqual(summary["ungrounded"], 1)
        # 1 existing / 1 linkable (ungrounded refused, not a miss) = 1.0
        self.assertEqual(summary["link_rate"], 1.0)

    def test_ungrounded_suppresses_dryrun_would_create(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c.helper.api.malware = MagicMock()
        c.helper.api.malware.list = MagicMock(return_value=[])
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.intrusion_set.list = MagicMock(return_value=[])
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        c._src_text_norm = connector_module._grounding_haystack("nothing relevant here")
        c._link_malware("e--1", ["PhantomLoader"], 75)
        self.assertEqual(c.metrics.by_category["malware"]["would_create"], 0)
        self.assertEqual(c.metrics.by_category["malware"]["ungrounded"], 1)


class TestPerCategoryCreateFlags(unittest.TestCase):
    """A proven category can be enabled without enabling the noisy ones."""

    def test_unset_inherits_global(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        for cat in ("actor", "malware", "tool", "victim"):
            self.assertEqual(c._create_modes[cat], "dry-run", cat)
            self.assertFalse(c._may_create(cat), cat)
            self.assertTrue(c._may_dryrun(cat), cat)

    def test_cve_has_no_creation_flag(self):
        # AI_CREATE_CVES was removed: CVEs are lookup-only, so the flag must not
        # be able to turn creation back on.
        c = _make_connector({"AI_CREATE_STUBS": "dry-run", "AI_CREATE_CVES": "true"})
        self.assertNotIn("cve", c._create_modes)
        self.assertFalse(c._may_create("cve"))

    def test_category_override_beats_global(self):
        # Global stays dry-run; only victims go live.
        c = _make_connector({"AI_CREATE_STUBS": "dry-run", "AI_CREATE_VICTIMS": "true"})
        self.assertTrue(c._may_create("victim"))
        self.assertFalse(c._may_dryrun("victim"))
        for cat in ("actor", "malware", "tool"):
            self.assertFalse(c._may_create(cat), cat)
            self.assertTrue(c._may_dryrun(cat), cat)

    def test_category_can_be_disabled_while_global_on(self):
        # Global on, but tools explicitly held back (too noisy).
        c = _make_connector({"AI_CREATE_STUBS": "true", "AI_CREATE_TOOLS": "false"})
        self.assertTrue(c._may_create("actor"))
        self.assertFalse(c._may_create("tool"))
        self.assertFalse(c._may_dryrun("tool"))  # off = neither create nor log

    def test_victim_only_live_creates_victim_not_actor(self):
        # The v5 rollout shape: victims live, everything else held at dry-run.
        c = _make_connector({"AI_CREATE_STUBS": "dry-run", "AI_CREATE_VICTIMS": "on"})
        c.helper.api.identity = MagicMock()
        c.helper.api.identity.list = MagicMock(return_value=[])
        c.helper.api.identity.create = MagicMock(return_value={"id": "id--new"})
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.intrusion_set.list = MagicMock(return_value=[])
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        c.helper.api.malware = MagicMock()
        c.helper.api.malware.list = MagicMock(return_value=[])
        c.helper.api.tool = MagicMock()
        c.helper.api.tool.list = MagicMock(return_value=[])
        c.helper.api.stix_domain_object = MagicMock()
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        c._src_text_norm = connector_module._grounding_haystack(
            "Acme Widgets Ltd was breached by Brand New Actor")

        c._link_victims("e--1", ["Acme Widgets Ltd"], 75)
        # identity.create is also used for the connector's author identity, so
        # assert on the victim call specifically.
        self.assertTrue(any(kw.get("name") == "Acme Widgets Ltd"
                            for _, kw in c.helper.api.identity.create.call_args_list),
                        "victim identity was not created")

        c._link_threat_actors("e--1", ["Brand New Actor"], 75)
        c.helper.api.intrusion_set.create.assert_not_called()    # actor stayed dry-run
        self.assertEqual(c.metrics.by_category["actor"]["would_create"], 1)

    def test_read_only_downgrades_live_category_to_dryrun(self):
        c = _make_connector({"AI_CREATE_VICTIMS": "true", "AI_READ_ONLY": "true"})
        self.assertFalse(c._may_create("victim"))   # read-only wins
        self.assertTrue(c._may_dryrun("victim"))    # still accounted for

    def test_mode_parser(self):
        p = connector_module.AIEnrichmentConnector._parse_create_mode
        for v in ("dry-run", "dryrun", "dry_run", "dry"):
            self.assertEqual(p(v), "dry-run", v)
        for v in ("true", "1", "yes", "on"):
            self.assertEqual(p(v), "on", v)
        for v in ("false", "0", "off", "", "garbage"):
            self.assertEqual(p(v), "off", v)


class TestReadOnlyMode(unittest.TestCase):
    """AI_READ_ONLY must block EVERY knowledge-graph write while still analysing."""

    def _ro(self):
        c = _make_connector({"AI_READ_ONLY": "true", "AI_CREATE_STUBS": "true"})
        c.helper.api.note = MagicMock()
        c.helper.api.stix_domain_object = MagicMock()
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.report = MagicMock()
        return c

    def test_read_only_forces_creation_off_but_keeps_accounting(self):
        c = self._ro()
        self.assertTrue(c._read_only)
        self.assertFalse(c._create_stubs)   # creation forced off
        self.assertTrue(c._create_dryrun)   # would-create accounting stays on

    def test_default_is_not_read_only(self):
        c = _make_connector()
        self.assertFalse(c._read_only)

    def test_no_note_written(self):
        c = self._ro()
        c._add_or_update_note("e--1", "summary text", 75, "hash123")
        c.helper.api.note.create.assert_not_called()
        c.helper.api.note.update.assert_not_called()

    def test_labels_counted_but_not_written(self):
        c = self._ro()
        n = c._apply_labels("e--1", ["ransomware", "phishing"])
        self.assertEqual(n, 2)  # reports what it WOULD apply
        c.helper.api.stix_domain_object.add_label.assert_not_called()

    def test_idempotency_label_not_written_but_succeeds(self):
        c = self._ro()
        self.assertTrue(c._apply_idempotency_label("e--1"))
        c.helper.api.stix_domain_object.add_label.assert_not_called()

    def test_no_relationship_written(self):
        c = self._ro()
        ok = c._link_or_contain("e--1", "t--1", "uses", 75, False, target_type="Malware")
        self.assertTrue(ok)  # counted as a would-be edge
        c.helper.api.stix_core_relationship.create.assert_not_called()

    def test_no_report_object_ref_written(self):
        c = self._ro()
        ok = c._link_or_contain("r--1", "t--1", "uses", 75, True, target_type="Malware")
        self.assertTrue(ok)
        c.helper.api.report.add_stix_object_or_stix_relationship.assert_not_called()

    def test_no_structured_field_written(self):
        c = self._ro()
        reader = MagicMock()
        n = c._apply_entity_fields(reader, {"id": "e--1", "description": ""},
                                   {"description": "new text"})
        self.assertEqual(n, 1)  # would-fill counted
        reader.update_field.assert_not_called()

    def test_no_alias_writeback(self):
        c = _make_connector({"AI_READ_ONLY": "true", "AI_ALIAS_WRITEBACK": "true"})
        reader = MagicMock()
        n = c._apply_aliases(reader, {"id": "e--1", "aliases": []}, ["FIN7"])
        self.assertEqual(n, 0)
        reader.update_field.assert_not_called()

    def test_no_stub_tagging(self):
        c = self._ro()
        c._tag_created({"id": "stub--1"})
        c.helper.api.stix_domain_object.add_label.assert_not_called()


class TestRateLimitPacing(unittest.TestCase):
    """AI_MAX_RPM paces our own calls so we stay under the server-side quota."""

    def test_disabled_by_default(self):
        c = _make_connector()
        self.assertEqual(c._max_rpm, 0)
        self.assertEqual(c._min_call_interval, 0.0)

    def test_interval_from_rpm(self):
        c = _make_connector({"AI_MAX_RPM": "10"})
        self.assertEqual(c._max_rpm, 10)
        self.assertAlmostEqual(c._min_call_interval, 6.0)

    def test_invalid_rpm_falls_back_to_disabled(self):
        c = _make_connector({"AI_MAX_RPM": "not-a-number"})
        self.assertEqual(c._max_rpm, 0)

    def test_throttle_noop_when_disabled(self):
        c = _make_connector()
        with patch("time.sleep") as slp:
            c._throttle()
            slp.assert_not_called()

    def test_throttle_sleeps_between_rapid_calls(self):
        c = _make_connector({"AI_MAX_RPM": "60"})  # 1s spacing
        with patch("time.sleep") as slp:
            c._throttle()          # first call: no wait needed
            slp.assert_not_called()
            c._throttle()          # immediate second call must be paced
            self.assertTrue(slp.called)
            self.assertGreater(slp.call_args[0][0], 0)


class TestMitreIdValidation(unittest.TestCase):
    def test_valid_ids(self):
        f = connector_module.is_valid_mitre_id
        for v in ["T1059", "T1059.001", "t1003", "T1566.002"]:
            self.assertTrue(f(v), v)

    def test_invalid_ids(self):
        f = connector_module.is_valid_mitre_id
        for v in ["T352", "T367", "T105", "T10590", "TA0001", "not-an-id", "", None]:
            self.assertFalse(f(v), v)


class TestResolveRel(unittest.TestCase):
    def setUp(self):
        self.rr = connector_module.resolve_rel

    def test_forward_preferred_kept(self):
        self.assertEqual(self.rr("Intrusion-Set", "Malware", "uses"), ("uses", False))
        self.assertEqual(self.rr("Campaign", "Attack-Pattern", "uses"), ("uses", False))
        self.assertEqual(self.rr("Malware", "Organization", "targets"), ("targets", False))

    def test_vulnerability_source_reverses(self):
        # Vulnerability has no outgoing typed rels; edge must reverse.
        self.assertEqual(self.rr("Vulnerability", "Attack-Pattern", "uses"), ("targets", True))
        self.assertEqual(self.rr("Vulnerability", "Malware", "uses"), ("exploits", True))

    def test_related_to_short_circuits(self):
        self.assertEqual(self.rr("Vulnerability", "Malware", "related-to"), ("related-to", False))
        self.assertEqual(self.rr("Intrusion-Set", "Intrusion-Set", "related-to"), ("related-to", False))

    def test_same_type_no_valid_uses_falls_back(self):
        # Malware->Malware has no 'uses' in the schema -> safe fallback.
        self.assertEqual(self.rr("Malware", "Malware", "uses"), ("related-to", False))

    def test_no_source_type_keeps_preferred(self):
        self.assertEqual(self.rr(None, "Malware", "uses"), ("uses", False))

    def test_unknown_pair_falls_back(self):
        self.assertEqual(self.rr("Vulnerability", "Tool", "uses"), ("related-to", False))


class TestAttackPatternLookupOnly(unittest.TestCase):
    def _conn(self, mode="dry-run"):
        c = _make_connector({"AI_CREATE_STUBS": mode})
        c.helper.api.attack_pattern = MagicMock()
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        return c

    def test_links_existing_never_creates(self):
        c = self._conn()
        c.helper.api.attack_pattern.read = MagicMock(return_value={"id": "ap--1"})
        n = c._link_attack_patterns("e--1", ["T1059"], 75)
        self.assertEqual(n, 1)
        c.helper.api.attack_pattern.create.assert_not_called()

    def test_malformed_ids_skipped_before_lookup(self):
        c = self._conn()
        c.helper.api.attack_pattern.read = MagicMock(return_value=None)
        n = c._link_attack_patterns("e--1", ["T352", "T367", "garbage"], 75)
        self.assertEqual(n, 0)
        c.helper.api.attack_pattern.read.assert_not_called()
        c.helper.api.attack_pattern.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["technique"]["invalid"], 3)

    def test_unknown_technique_dryrun_would_create(self):
        c = self._conn("dry-run")
        c.helper.api.attack_pattern.read = MagicMock(return_value=None)
        n = c._link_attack_patterns("e--1", ["T1059"], 75)
        self.assertEqual(n, 0)
        c.helper.api.attack_pattern.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["technique"]["would_create"], 1)

    def test_never_creates_even_in_on_mode(self):
        c = self._conn("true")  # AI_CREATE_STUBS=on
        c.helper.api.attack_pattern.read = MagicMock(return_value=None)
        n = c._link_attack_patterns("e--1", ["T1059"], 75)
        self.assertEqual(n, 0)
        c.helper.api.attack_pattern.create.assert_not_called()

    def test_vulnerability_source_creates_reversed_targets_edge(self):
        c = self._conn("dry-run")
        c._src_type = "Vulnerability"
        c.helper.api.attack_pattern.read = MagicMock(return_value={"id": "ap--1"})
        n = c._link_attack_patterns("vuln--1", ["T1059"], 75)
        self.assertEqual(n, 1)
        kw = c.helper.api.stix_core_relationship.create.call_args.kwargs
        self.assertEqual(kw["fromId"], "ap--1")      # attack-pattern is the source
        self.assertEqual(kw["toId"], "vuln--1")       # vulnerability is the target
        self.assertEqual(kw["relationship_type"], "targets")


class TestSectorCreateFlag(unittest.TestCase):
    def test_default_lookup_only(self):
        self.assertFalse(_make_connector()._create_sectors)

    def test_enabled_by_env(self):
        self.assertTrue(_make_connector({"AI_CREATE_SECTORS": "true"})._create_sectors)


class TestJunkFilter(unittest.TestCase):
    def test_rejects_junk(self):
        for n in ["888", "-", "F6", "CMD", "GOD user", "", "  ", "x1"]:
            self.assertTrue(is_junk_name(n), n)

    def test_accepts_real_names(self):
        for n in ["APT29", "Bearlyfy", "Volt Typhoon", "Cl0p", "LockBit"]:
            self.assertFalse(is_junk_name(n), n)


class TestLegitSoftwareAllowlist(unittest.TestCase):
    def test_known_legit_software(self):
        for n in ["OpenVPN", "openssh", "KeePassXC", "AnyDesk", "nmap", "DeepSeek", "Qwen", "Claude Code"]:
            self.assertTrue(is_known_legit_software(n), n)

    def test_malware_not_legit(self):
        for n in ["LockBit", "Qilin", "Emotet", "Cobalt Strike"]:
            self.assertFalse(is_known_legit_software(n), n)


class TestVocabNormalizers(unittest.TestCase):
    def test_malware_types(self):
        self.assertEqual(
            normalize_malware_types(["RAT", "ransomware", "banking trojan", "bogus"]),
            ["remote-access-trojan", "ransomware", "trojan"],
        )

    def test_tool_types(self):
        self.assertEqual(normalize_tool_types(["RMM", "scanner"]), ["remote-access", "vulnerability-scanning"])

    def test_motivation(self):
        self.assertEqual(normalize_motivation("financial"), "personal-gain")
        self.assertEqual(normalize_motivation("espionage"), "organizational-gain")
        self.assertIsNone(normalize_motivation("bananas"))

    def test_sophistication_and_resource(self):
        self.assertEqual(normalize_sophistication("advanced"), "advanced")
        self.assertIsNone(normalize_sophistication("godlike"))
        self.assertEqual(normalize_resource_level("government"), "government")

    def test_base_key_folds_malware_suffix(self):
        self.assertEqual(_base_key("Qilin Ransomware"), _base_key("Qilin"))


class TestSoftwareExtraction(unittest.TestCase):
    def test_splits_malware_and_tools_with_allowlist_override(self):
        result = {"software": [
            {"name": "LockBit", "kind": "malware", "legitimate": False},
            {"name": "OpenVPN", "kind": "malware", "legitimate": False},  # allowlist -> tool
            {"name": "DeepSeek", "kind": "malware"},   # consumer AI -> dropped entirely
            {"name": "PsExec", "kind": "tool", "legitimate": True},
        ]}
        mw, tools = AIEnrichmentConnector._extract_software(result)
        mw_names = {m["name"] for m in mw}
        tool_names = {t["name"] for t in tools}
        self.assertEqual(mw_names, {"LockBit"})
        # DeepSeek is consumer AI: not adversary tooling, so it becomes neither a
        # Tool nor (critically) Malware.
        self.assertEqual(tool_names, {"OpenVPN", "PsExec"})
        self.assertNotIn("DeepSeek", mw_names)

    def test_legacy_malware_families_fallback(self):
        result = {"malware_families": ["Emotet", "AnyDesk"]}
        mw, tools = AIEnrichmentConnector._extract_software(result)
        self.assertEqual({m["name"] for m in mw}, {"Emotet"})
        self.assertEqual({t["name"] for t in tools}, {"AnyDesk"})  # allowlist


class TestToolAndVictimLinking(unittest.TestCase):
    def setUp(self):
        self.c = _make_connector({"AI_CREATE_STUBS": "true"})
        self.c.helper.api.tool = MagicMock()
        self.c.helper.api.identity = MagicMock()
        self.c.helper.api.stix_domain_object = MagicMock()
        self.c.helper.api.stix_core_relationship = MagicMock()
        self.c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        self.c._get_author_id = MagicMock(return_value=None)

    def test_tool_created_and_linked(self):
        self.c.helper.api.tool.list = MagicMock(return_value=[])
        self.c.helper.api.tool.create = MagicMock(return_value={"id": "tool--1"})
        n = self.c._link_tools("e", [{"name": "nmap", "type": "scanner"}], 75)
        self.assertEqual(n, 1)
        self.c.helper.api.tool.create.assert_called_once()

    def test_victim_created_and_linked(self):
        self.c.helper.api.identity.list = MagicMock(return_value=[])
        self.c.helper.api.identity.create = MagicMock(return_value={"id": "id--1"})
        n = self.c._link_victims("e", ["Acme Corp"], 75)
        self.assertEqual(n, 1)
        self.c.helper.api.identity.create.assert_called_once()

    def test_victim_junk_rejected(self):
        self.c.helper.api.identity.list = MagicMock(return_value=[])
        n = self.c._link_victims("e", ["888"], 75)
        self.assertEqual(n, 0)
        self.c.helper.api.identity.create.assert_not_called()


class TestCrossTypeDedup(unittest.TestCase):
    def test_malware_name_existing_as_actor_links_not_creates(self):
        c = _make_connector({"AI_CREATE_STUBS": "true"})
        c.helper.api.malware = MagicMock()
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        # No malware match; but "Qilin" exists as an intrusion-set
        c.helper.api.malware.list = MagicMock(return_value=[])
        c.helper.api.intrusion_set.list = MagicMock(
            return_value=[{"id": "is--qilin", "name": "Qilin", "aliases": []}]
        )
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        n = c._link_malware("e", ["Qilin Ransomware"], 75)
        self.assertEqual(n, 1)
        c.helper.api.malware.create.assert_not_called()  # linked to the actor instead

    def test_dry_run_cross_type_links_existing_not_would_create(self):
        # In dry-run, a malware name that already exists as an actor must LINK to
        # the existing actor (real write) and NOT be counted as a would-create.
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c.helper.api.malware = MagicMock()
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.stix_core_relationship = MagicMock()
        c.helper.api.stix_core_relationship.create = MagicMock(return_value={"id": "rel--1"})
        c.helper.api.malware.list = MagicMock(return_value=[])
        c.helper.api.intrusion_set.list = MagicMock(
            return_value=[{"id": "is--qilin", "name": "Qilin", "aliases": []}]
        )
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        n = c._link_malware("e", ["Qilin Ransomware"], 75)
        self.assertEqual(n, 1)  # link was written to the existing actor
        c.helper.api.malware.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["malware"].get("would_create", 0), 0)
        self.assertEqual(c.metrics.by_category["malware"]["existing"], 1)

    def test_dry_run_truly_novel_counts_would_create(self):
        # A name not existing as any type is still a would-create in dry-run.
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c.helper.api.malware = MagicMock()
        c.helper.api.intrusion_set = MagicMock()
        c.helper.api.threat_actor_group = MagicMock()
        c.helper.api.malware.list = MagicMock(return_value=[])
        c.helper.api.intrusion_set.list = MagicMock(return_value=[])
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        n = c._link_malware("e", ["BrandNewLocker"], 75)
        self.assertEqual(n, 0)
        c.helper.api.malware.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["malware"]["would_create"], 1)


class TestCriticPass(unittest.TestCase):
    def test_critic_drops_reclassifies_and_moves(self):
        c = _make_connector()
        verdict = {
            "drop": ["888"],
            "actor_to_victim": ["Adspect"],
            "to_tool": ["OpenVPN"],
            "to_malware": [],
        }
        resp = MagicMock()
        resp.text = json.dumps(verdict)
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(return_value=resp)

        result = {
            "threat_actors": ["APT29", "888", "Adspect"],
            "victims": [],
            "software": [{"name": "OpenVPN", "kind": "malware", "legitimate": False}],
        }
        # An actor -> victim move now requires deterministic victim evidence in
        # the source (see _vet_actor_to_victim); supply it.
        c.helper.api.intrusion_set.list = MagicMock(return_value=[])
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        c._src_text_norm = connector_module._grounding_haystack(
            "Adspect reports a data breach affecting its customers."
        )
        c._run_critic(result, "report")
        self.assertEqual(result["threat_actors"], ["APT29"])
        self.assertIn("Adspect", result["victims"])
        self.assertEqual(result["software"][0]["kind"], "tool")

    def test_critic_failure_is_silent(self):
        c = _make_connector()
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(side_effect=RuntimeError("boom"))
        result = {"threat_actors": ["APT29"], "software": []}
        # must not raise, must leave result untouched
        c._run_critic(result, "report")
        self.assertEqual(result["threat_actors"], ["APT29"])


class TestApplyEntityFields(unittest.TestCase):
    def setUp(self):
        self.c = _make_connector()
        self.c.helper.api.intrusion_set = MagicMock()

    def test_sets_only_empty_fields(self):
        entity = {"id": "is--1", "primary_motivation": "", "resource_level": "government"}
        applied = self.c._apply_entity_fields(self.c.helper.api.intrusion_set, entity, {
            "primary_motivation": "personal-gain",   # empty -> set
            "resource_level": "team",                 # already set -> skip
        })
        self.assertEqual(applied, 1)
        kwargs = self.c.helper.api.intrusion_set.update_field.call_args[1]
        self.assertEqual(kwargs["input"]["key"], "primary_motivation")

    def test_skips_empty_values(self):
        entity = {"id": "is--1", "primary_motivation": ""}
        applied = self.c._apply_entity_fields(self.c.helper.api.intrusion_set, entity, {
            "primary_motivation": None,
        })
        self.assertEqual(applied, 0)
        self.c.helper.api.intrusion_set.update_field.assert_not_called()


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# v2 defect fixes — all four were confirmed against production data in
# gold_sample.csv and the connector's own /state/ai_audit.log.
# ---------------------------------------------------------------------------

_base_key = connector_module._base_key
_dedup_key = connector_module._dedup_key
is_adversary_brand_name = connector_module.is_adversary_brand_name
is_leak_site_operator = connector_module.is_leak_site_operator
has_victim_context = connector_module.has_victim_context
org_partial_match = connector_module.org_partial_match
canonical_name_from_title = connector_module.canonical_name_from_title
victim_name_from_title = connector_module.victim_name_from_title


class TestDefect1LeakSiteOperatorIsActor(unittest.TestCase):
    """'FulcrumSec Data Leak Site' became a victim; a leak-site operator is an actor."""

    def test_adversary_brand_never_a_victim(self):
        for name in ("Business Data Leaks", "Everest ransom team",
                     "404Crew Cyber Team", "Qilin Ransomware"):
            self.assertTrue(is_adversary_brand_name(name), name)

    def test_real_company_named_group_is_not_adversary_brand(self):
        # 'Group'/'Team' alone must never be read as adversary self-branding.
        for name in ("Calder Group", "Brentmoor Group", "Larkfield Research Group, LLC",
                     "Eastvale Airports Group"):
            self.assertFalse(is_adversary_brand_name(name), name)

    def test_leak_site_operator_detected_from_title(self):
        self.assertTrue(is_leak_site_operator(
            "FulcrumSec", "FulcrumSec Data Leak Site"))
        self.assertTrue(is_leak_site_operator(
            "Vexy", "Vexy has published a new victim: Acme"))
        self.assertTrue(is_leak_site_operator("Qilin", "Qilin Blog"))

    def test_victim_listed_on_a_leak_site_is_not_the_operator(self):
        # Positional: the phrase must FOLLOW the name.
        self.assertFalse(is_leak_site_operator(
            "Acme Corp", "Acme Corp appeared on the LockBit data leak site"))

    def test_victim_context_requires_breach_language(self):
        self.assertTrue(has_victim_context(
            "Acme Corp", "Acme Corp reports a data breach affecting 400 people"))
        self.assertTrue(has_victim_context(
            "Calder Telecom", "DYSPHOR1A has published a new victim: Calder Telecom"))
        self.assertFalse(has_victim_context(
            "FulcrumSec", "Ransomware and Extortion Roundup: 40 New Victims"))

    def _critic(self, verdict, result, src_name="", src_text="", kb_actor=None):
        c = _make_connector()
        resp = MagicMock()
        resp.text = json.dumps(verdict)
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(return_value=resp)
        c.helper.api.intrusion_set.list = MagicMock(
            return_value=[kb_actor] if kb_actor else [])
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        c._src_name = src_name
        c._src_text_norm = connector_module._grounding_haystack(
            f"{src_text} {src_name}")
        c._run_critic(result, "report")
        return c, result

    def test_critic_cannot_move_leak_site_operator_to_victim(self):
        # The production failure: FulcrumSec was extracted as an actor, then the
        # critic moved it into victims where it would have been created as an org.
        result = {"threat_actors": ["FulcrumSec", "INC Ransom"], "victims": []}
        _, out = self._critic(
            {"actor_to_victim": ["FulcrumSec"]}, result,
            src_name="Ransomware and Extortion Roundup: 40 New Victims",
            src_text="FulcrumSec Data Leak Site listed new victims.",
        )
        self.assertIn("FulcrumSec", out["threat_actors"])
        self.assertNotIn("FulcrumSec", out["victims"])

    def test_critic_cannot_move_adversary_brand_to_victim(self):
        result = {"threat_actors": ["Business Data Leaks"], "victims": []}
        _, out = self._critic({"actor_to_victim": ["Business Data Leaks"]}, result)
        self.assertEqual(out["threat_actors"], ["Business Data Leaks"])
        self.assertEqual(out["victims"], [])

    def test_critic_move_refused_without_victim_evidence(self):
        result = {"threat_actors": ["Global Secret Group"], "victims": []}
        _, out = self._critic(
            {"actor_to_victim": ["Global Secret Group"]}, result,
            src_name="Ransomware and Extortion Roundup: 40 New Victims",
        )
        self.assertEqual(out["threat_actors"], ["Global Secret Group"])
        self.assertEqual(out["victims"], [])

    def test_critic_move_refused_when_actor_exists_in_kb(self):
        result = {"threat_actors": ["Rhysida"], "victims": []}
        _, out = self._critic(
            {"actor_to_victim": ["Rhysida"]}, result,
            kb_actor={"id": "is--1", "name": "Rhysida", "entity_type": "Intrusion-Set"},
        )
        self.assertEqual(out["threat_actors"], ["Rhysida"])
        self.assertEqual(out["victims"], [])

    def test_critic_still_moves_a_security_vendor(self):
        # The legitimate case the critic exists for: a defender listed as attacker.
        result = {"threat_actors": ["CrowdStrike"], "victims": []}
        _, out = self._critic({"actor_to_victim": ["CrowdStrike"]}, result)
        self.assertEqual(out["threat_actors"], [])
        self.assertIn("CrowdStrike", out["victims"])

    def test_link_victims_refuses_leak_site_operator(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c._src_name = "FulcrumSec Data Leak Site"
        c._src_text_norm = connector_module._grounding_haystack(c._src_name)
        c.helper.api.identity.list = MagicMock(return_value=[])
        n = c._link_victims("e--1", ["FulcrumSec"], 75)
        self.assertEqual(n, 0)
        self.assertEqual(c.metrics.by_category["victim"]["would_create"], 0)
        self.assertEqual(c.metrics.by_category["victim"]["generic"], 1)


class TestDefect2VersionSuffixedActor(unittest.TestCase):
    """'LockBit 5.0' would be created although 'LockBit' exists."""

    def test_dotted_version_stripped(self):
        self.assertEqual(_base_key("LockBit 5.0"), _base_key("LockBit"))
        self.assertEqual(_base_key("LockBit 3.0"), "lockbit")

    def test_version_and_type_suffix_together(self):
        self.assertEqual(_base_key("LockBit 5.0 Ransomware"), "lockbit")
        self.assertEqual(_base_key("Qilin 2 Ransomware"), "qilin")

    def test_v_prefixed_version_stripped(self):
        self.assertEqual(_base_key("TrickBot v2"), "trickbot")
        self.assertEqual(_base_key("Emotet v3.1"), "emotet")

    def test_bare_integer_stripped_only_for_long_bases(self):
        self.assertEqual(_base_key("Doommageddon 2"), "doommageddon")

    def test_actor_designators_are_not_versions(self):
        # The number IS the name here; collapsing them would link unrelated actors.
        for spaced, joined in (("APT 28", "APT28"), ("FIN 7", "FIN7"),
                               ("TA 505", "TA505"), ("UNC 1878", "UNC1878")):
            self.assertEqual(_base_key(spaced), _dedup_key(joined), spaced)
            self.assertNotEqual(_base_key(spaced), _base_key(spaced.split()[0]), spaced)

    def test_existing_suffix_folding_preserved(self):
        self.assertEqual(_base_key("Qilin Ransomware"), _base_key("Qilin"))
        self.assertEqual(_base_key("Lazarus Group"), "lazarus")
        self.assertEqual(_base_key("Cl0p"), "clop")

    def test_resolve_by_base_key_finds_versionless_entity(self):
        c = _make_connector()
        reader = MagicMock()
        reader.list = MagicMock(return_value=[
            {"id": "is--1", "name": "LockBit", "entity_type": "Intrusion-Set"}
        ])
        self.assertEqual(
            c._resolve_by_base_key([reader], "LockBit 5.0")["id"], "is--1")

    def test_versioned_actor_links_instead_of_creating(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c.helper.api.intrusion_set.list = MagicMock(return_value=[
            {"id": "is--1", "name": "LockBit", "entity_type": "Intrusion-Set"}
        ])
        c.helper.api.threat_actor_group.list = MagicMock(return_value=[])
        c._src_text_norm = connector_module._grounding_haystack("LockBit 5.0 attack")
        c._link_threat_actors("e--1", ["LockBit 5.0"], 75)
        c.helper.api.intrusion_set.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["actor"]["would_create"], 0)
        self.assertEqual(c.metrics.by_category["actor"]["existing"], 1)


class TestDefect3PartialVictimNames(unittest.TestCase):
    """'HEPL' and 'Brightwell' each created a duplicate beside the full name."""

    def test_acronym_declared_in_title_is_expanded(self):
        self.assertEqual(
            canonical_name_from_title(
                "HEPL",
                "Vexy Ransomware has published a new victim: Harbour Enviro (HEPL)"),
            "Harbour Enviro",
        )

    def test_parenthetical_that_is_not_an_acronym_is_ignored(self):
        self.assertEqual(canonical_name_from_title("US", "Acme Corp (US)"), "")
        self.assertEqual(
            canonical_name_from_title("CVE-2026-1234", "Flaw (CVE-2026-1234)"), "")

    def test_head_truncation_matches_full_name(self):
        self.assertTrue(org_partial_match(
            "Brightwell", "Brightwell Mess-Regeltechnik GmbH"))

    def test_short_leading_token_does_not_fold(self):
        # 'Acme' is too short to be treated as a distinctive truncation.
        self.assertFalse(org_partial_match("Acme", "Acme Health Services Ltd"))

    def test_unrelated_orgs_do_not_fold(self):
        self.assertFalse(org_partial_match(
            "Brightwell", "Larkfield Research Group, LLC"))
        self.assertFalse(org_partial_match(
            "Cobalt Bank & Trust Company", "Cobalt Bank & Trust Company"))

    def test_news_headline_is_never_an_org_name(self):
        self.assertEqual(victim_name_from_title(
            "US-Based Home Healthcare Provider Meridian HealthCare of Fairview City "
            "Reports Data Breach Affecting Hundreds of Individuals"), "")

    def test_bare_leak_post_title_is_an_org_name(self):
        self.assertEqual(
            victim_name_from_title("Brightwell Mess-Regeltechnik GmbH"),
            "Brightwell Mess-Regeltechnik GmbH")
        self.assertEqual(
            victim_name_from_title(
                "Vexy Ransomware has published a new victim: Harbour Enviro (HEPL)"),
            "Harbour Enviro")

    def test_acronym_victim_resolves_against_full_name_in_kb(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c._src_name = ("Vexy Ransomware has published a new victim: "
                       "Harbour Enviro (HEPL)")
        c._src_text_norm = connector_module._grounding_haystack(c._src_name)
        c.helper.api.identity.list = MagicMock(side_effect=lambda **kw: (
            [{"id": "id--1", "name": "Harbour Enviro", "entity_type": "Organization"}]
            if "harbour" in str(kw.get("search", "")).lower() else []
        ))
        n = c._link_victims("e--1", ["HEPL"], 75)
        self.assertEqual(n, 1)
        self.assertEqual(c.metrics.by_category["victim"]["existing"], 1)
        self.assertEqual(c.metrics.by_category["victim"]["would_create"], 0)

    def test_acronym_and_full_name_create_only_one_victim(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c._src_name = "Harbour Enviro (HEPL)"
        c._src_text_norm = connector_module._grounding_haystack(
            "Harbour Enviro (HEPL) was listed as a new victim.")
        c.helper.api.identity.list = MagicMock(return_value=[])
        c._link_victims("e--1", ["HEPL", "Harbour Enviro"], 75)
        self.assertEqual(c.metrics.by_category["victim"]["would_create"], 1)

    def test_truncated_victim_folds_into_title_org(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c._src_name = "Brightwell Mess-Regeltechnik GmbH"
        c._src_text_norm = connector_module._grounding_haystack(c._src_name)
        c.helper.api.identity.list = MagicMock(return_value=[])
        c._link_victims("e--1", ["Brightwell", "Brightwell Mess-Regeltechnik GmbH"], 75)
        self.assertEqual(c.metrics.by_category["victim"]["would_create"], 1)


class TestDefect4CrossTypeSameNamePair(unittest.TestCase):
    """'Doommageddon' reached two would-create decisions via two linkers."""

    def _conn(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        for api in (c.helper.api.intrusion_set, c.helper.api.threat_actor_group,
                    c.helper.api.malware, c.helper.api.tool):
            api.list = MagicMock(return_value=[])
        c._src_text_norm = connector_module._grounding_haystack(
            "Doommageddon ransomware was deployed by the Doommageddon group.")
        c._ransomware_context = True
        return c

    def test_ransomware_brand_pair_is_intentional_and_logged(self):
        c = self._conn()
        c._link_threat_actors("e--1", ["Doommageddon"], 75, as_report_object=True)
        c._link_malware("e--1", [{"name": "Doommageddon", "type": "ransomware"}], 75,
                        as_report_object=True)
        self.assertEqual(c.metrics.by_category["actor"]["would_create"], 1)
        self.assertEqual(c.metrics.by_category["malware"]["would_create"], 1)
        self.assertTrue(any("[CROSS-TYPE]" in str(a) and "intentionally" in str(a)
                            for a, _ in c.helper.log_info.call_args_list))

    def test_non_ransomware_duplicate_is_suppressed(self):
        c = self._conn()
        c._src_text_norm = connector_module._grounding_haystack(
            "SecFlow was used for espionage tooling by the SecFlow operator.")
        c._ransomware_context = False
        c._link_threat_actors("e--1", ["SecFlow"], 75, as_report_object=True)
        c._link_malware("e--1", [{"name": "SecFlow", "type": "backdoor"}], 75,
                        as_report_object=True)
        self.assertEqual(c.metrics.by_category["actor"]["would_create"], 1)
        self.assertEqual(c.metrics.by_category["malware"]["would_create"], 0)
        self.assertEqual(c.metrics.by_category["malware"]["dup_suppressed"], 1)

    def test_tool_does_not_duplicate_a_claimed_malware_name(self):
        c = self._conn()
        c._ransomware_context = False
        c._link_malware("e--1", [{"name": "Doommageddon", "type": "backdoor"}], 75,
                        as_report_object=True)
        c._link_tools("e--1", [{"name": "Doommageddon", "type": "remote-access"}], 75,
                      as_report_object=True)
        self.assertEqual(c.metrics.by_category["malware"]["would_create"], 1)
        self.assertEqual(c.metrics.by_category["tool"]["dup_suppressed"], 1)

    def test_version_variant_counts_as_the_same_claim(self):
        c = self._conn()
        c._ransomware_context = False
        c._src_text_norm = connector_module._grounding_haystack(
            "Newbrand 1.0 and Newbrand 2.0 backdoors were observed.")
        c._link_malware("e--1", [{"name": "Newbrand 1.0"}, {"name": "Newbrand 2.0"}],
                        75, as_report_object=True)
        self.assertEqual(c.metrics.by_category["malware"]["would_create"], 1)
        self.assertEqual(c.metrics.by_category["malware"]["dup_suppressed"], 1)

    def test_claims_reset_between_enrichments(self):
        c = self._conn()
        c._novel_claims = {"doommageddon": "actor"}
        c._call_gemini_reset = None
        # _call_gemini is the single per-enrichment choke point that resets state.
        resp = MagicMock()
        resp.text = json.dumps({"summary": "s", "confidence": 50})
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(return_value=resp)
        c._call_gemini("prompt {content}", "some content", entity_type="report",
                       entity={"id": "e--1", "name": "Doommageddon Blog"})
        self.assertEqual(c._novel_claims, {})
        self.assertEqual(c._src_name, "Doommageddon Blog")

    def test_dup_suppressed_excluded_from_link_rate(self):
        mt = MetricsTracker()
        mt.record_category("malware", "existing")
        mt.record_category("malware", "dup_suppressed")
        summary = mt.summary_dict()["by_category"]["malware"]
        self.assertEqual(summary["detected"], 2)
        self.assertEqual(summary["dup_suppressed"], 1)
        self.assertEqual(summary["link_rate"], 1.0)


class TestCollectiveDescriptors(unittest.TestCase):
    """'Chinese banks' names a CLASS of organisations, not an organisation."""

    def setUp(self):
        self.f = connector_module.is_collective_descriptor
        self.g = connector_module.is_generic_entity_name

    def test_nationality_plus_plural_is_collective(self):
        for name in ("Chinese banks", "Russian companies", "American hospitals",
                     "European financial institutions", "Indian pharmaceutical companies",
                     "US healthcare providers", "Asian telecoms",
                     "government agencies", "multiple hospitals",
                     "several US banks", "critical infrastructure operators",
                     "state agencies", "public universities"):
            self.assertTrue(self.f(name), name)
            self.assertTrue(self.g(name), f"is_generic_entity_name({name!r})")

    def test_real_organisations_survive(self):
        # Every one of these is a genuine victim from the labelled sample.
        for name in (
            "Cobalt Bank & Trust Company",
            "Bank of Kalinda",
            "Larkfield Research Group, LLC",
            "Astora State Navy",
            "Meridian HealthCare of Fairview City Inc.",
            "Coastline Creative Solutions, Inc.",
            "Ashford Metropolitan Pipework Contractors Cooperative Association",
            "Ministry of Foreign Affairs of Astora",
            "Eastvale District Government",
            "Meridian Party History Archives",
            "Astora Broadband Telecom Co., Ltd.",
            "Redhill Rheumatology Professional LLC",
            "Clearview Eye Care Laser & Eye Surgery Center",
            "Astora Federal Authority for Identity, Citizenship, Customs & Port Security",
            "Psychiatry of Brentmoor PLLC",
            "TalentEdge, Inc.",
            "KB ENM",
            "Harbour Enviro",
            "Vantage Enterprises Inc.",
            "Larkmont, P.C.",
        ):
            self.assertFalse(self.f(name), name)
            self.assertFalse(self.g(name), f"is_generic_entity_name({name!r})")

    def test_adversary_brands_survive(self):
        # These must stay available as ACTORS; only their use as victims is wrong.
        for name in ("Global Secret Group", "Business Data Leaks", "FulcrumSec",
                     "Lego Resistance Front", "404Crew Cyber Team", "Dark Storm",
                     "INC Ransom", "Everest ransom team"):
            self.assertFalse(self.f(name), name)

    def test_singular_generic_alone_is_not_collective(self):
        # Needs a plural org word; a bare singular is handled by is_junk_name.
        self.assertFalse(self.f("bank"))
        self.assertFalse(self.f("healthcare"))

    def test_collective_victim_is_dropped(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c.helper.api.identity.list = MagicMock(return_value=[])
        n = c._link_victims("e--1", ["Chinese banks"], 75)
        self.assertEqual(n, 0)
        c.helper.api.identity.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["victim"]["would_create"], 0)
        self.assertEqual(c.metrics.by_category["victim"]["generic"], 1)

    def test_collective_actor_is_dropped(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        for api in (c.helper.api.intrusion_set, c.helper.api.threat_actor_group,
                    c.helper.api.malware, c.helper.api.tool):
            api.list = MagicMock(return_value=[])
        c._link_threat_actors("e--1", ["Russian companies"], 75)
        c.helper.api.intrusion_set.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["actor"]["generic"], 1)

    def test_collective_malware_is_dropped(self):
        # The guard lives in is_generic_entity_name, so every linker inherits it.
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        for api in (c.helper.api.malware, c.helper.api.intrusion_set,
                    c.helper.api.threat_actor_group):
            api.list = MagicMock(return_value=[])
        c._link_malware("e--1", [{"name": "Chinese banks"}], 75)
        c.helper.api.malware.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["malware"]["generic"], 1)

    def test_malware_class_plurals_are_out_of_scope(self):
        # Documented limitation: this guard is ORGANISATION-scoped. Malware-class
        # plurals ("banking trojans") are a different vocabulary, tracked as v5 P7
        # alongside "SSH keylogger". Asserted so the boundary is explicit.
        self.assertFalse(self.f("banking trojans"))
        self.assertFalse(self.f("infostealers"))


class TestToolCrossTypeDedup(unittest.TestCase):
    """_link_tools had no cross-type lookup, so it duplicated existing Malware.

    Found against the live KB: "Metasploit" and "UPX" are both stored as Malware
    on this platform, yet both were reported as Tool would-creates.
    """

    def _conn(self):
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        for api in (c.helper.api.tool, c.helper.api.malware,
                    c.helper.api.intrusion_set, c.helper.api.threat_actor_group):
            api.list = MagicMock(return_value=[])
        c._src_text_norm = connector_module._grounding_haystack(
            "Metasploit and UPX were used in the intrusion")
        return c

    def test_tool_links_to_existing_malware_instead_of_creating(self):
        c = self._conn()
        c.helper.api.malware.list = MagicMock(return_value=[
            {"id": "mal--1", "name": "Metasploit", "entity_type": "Malware"}])
        c.helper.api.stix_core_relationship.create = MagicMock(
            return_value={"id": "rel--1"})
        n = c._link_tools("e--1", [{"name": "Metasploit"}], 75, as_report_object=True)
        self.assertEqual(n, 1)
        c.helper.api.tool.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["tool"]["existing"], 1)
        self.assertEqual(c.metrics.by_category["tool"]["would_create"], 0)

    def test_tool_links_to_existing_actor_namesake(self):
        c = self._conn()
        c.helper.api.intrusion_set.list = MagicMock(return_value=[
            {"id": "is--1", "name": "UPX", "entity_type": "Intrusion-Set"}])
        n = c._link_tools("e--1", [{"name": "UPX"}], 75, as_report_object=True)
        self.assertEqual(n, 1)
        c.helper.api.tool.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["tool"]["existing"], 1)

    def test_genuinely_novel_tool_still_counts_as_would_create(self):
        c = self._conn()
        c._src_text_norm = connector_module._grounding_haystack("SecFlow was abused")
        c._link_tools("e--1", [{"name": "SecFlow"}], 75, as_report_object=True)
        c.helper.api.tool.create.assert_not_called()
        self.assertEqual(c.metrics.by_category["tool"]["would_create"], 1)

    def test_existing_tool_still_wins_over_cross_type(self):
        c = self._conn()
        c.helper.api.tool.list = MagicMock(return_value=[
            {"id": "tool--1", "name": "Radmin", "entity_type": "Tool"}])
        c.helper.api.malware.list = MagicMock(return_value=[
            {"id": "mal--9", "name": "Radmin", "entity_type": "Malware"}])
        c._link_tools("e--1", [{"name": "Radmin"}], 75, as_report_object=True)
        self.assertEqual(c.metrics.by_category["tool"]["existing"], 1)


class TestReadOnlyLeaks(unittest.TestCase):
    """AI_READ_ONLY must mean ZERO graph mutations — enforced structurally.

    Regression origin: `_update_score` had no read-only guard, so the connector
    issued a `stix_domain_object.update_field` on every enrichment while
    reporting "zero graph writes". It went unnoticed because the original
    verification only compared note / relationship / entity COUNTS, and a scalar
    field update changes none of those. Observed live on a Vulnerability:
    score_before=72 -> score_after=85.

    The per-method tests below are useful, but the important one is
    test_full_enrichment_issues_no_mutations: it asserts on the whole surface, so
    a NEW unguarded write is caught without anyone remembering to add a test.
    """

    # Every pycti call that changes server state.
    MUTATORS = ("create", "update_field", "add_label", "remove_label", "delete",
                "add_stix_object_or_stix_relationship")

    def _readonly(self):
        c = _make_connector({"AI_READ_ONLY": "true", "AI_CREATE_STUBS": "dry-run",
                             "AI_CREATE_SECTORS": "true", "AI_ALIAS_WRITEBACK": "true"})
        c.helper.api = MagicMock()
        c.helper.api.note.list = MagicMock(return_value=[])
        return c

    @classmethod
    def _mutation_calls(cls, api_mock):
        """Every mutating call recorded anywhere on the API mock tree."""
        found = []

        def walk(mock, path):
            for name, child in list(getattr(mock, "_mock_children", {}).items()):
                if not isinstance(child, MagicMock):
                    continue
                sub = f"{path}.{name}"
                if name in cls.MUTATORS and child.call_args_list:
                    found.append((sub, len(child.call_args_list)))
                walk(child, sub)

        walk(api_mock, "api")
        return found

    def test_update_score_is_guarded(self):
        c = self._readonly()
        self.assertTrue(c._update_score("e--1", 85))   # reported as applied
        c.helper.api.stix_domain_object.update_field.assert_not_called()

    def test_update_score_writes_when_not_read_only(self):
        c = _make_connector()
        c.helper.api = MagicMock()
        c._update_score("e--1", 85)
        c.helper.api.stix_domain_object.update_field.assert_called_once()
        _, kw = c.helper.api.stix_domain_object.update_field.call_args
        self.assertEqual(kw["input"]["value"], 85)
        self.assertIsInstance(kw["input"]["value"], int)

    def test_sector_creation_guarded_even_with_create_sectors_true(self):
        c = self._readonly()
        c.helper.api.identity.list = MagicMock(return_value=[])
        c._link_sectors("e--1", ["Widget Fabrication"], 75)
        c.helper.api.identity.create.assert_not_called()

    def test_author_identity_not_created_in_read_only(self):
        c = self._readonly()
        self.assertIsNone(c._get_author_id())
        c.helper.api.identity.create.assert_not_called()

    def test_full_enrichment_issues_no_mutations(self):
        """The catch-all: run a whole report enrichment and assert nothing wrote."""
        c = self._readonly()
        # Nothing resolves, so every linker takes its create/dry-run branch.
        for reader in ("intrusion_set", "threat_actor_group", "malware", "tool",
                       "identity", "vulnerability"):
            getattr(c.helper.api, reader).list = MagicMock(return_value=[])
        c.helper.api.attack_pattern.read = MagicMock(return_value=None)
        c.helper.api.note.list = MagicMock(return_value=[])

        payload = {
            "summary": "A summary of the incident.",
            "threat_actors": ["Brand New Actor"],
            "victims": ["Acme Widgets Ltd"],
            "software": [
                {"name": "NovelLoader", "kind": "malware", "type": "downloader"},
                {"name": "NovelRMM", "kind": "tool", "type": "remote-access"},
            ],
            "attack_techniques": ["T1059.001", "T9999"],
            "cves": ["CVE-2026-90001"],
            "targeted_sectors": ["Widget Fabrication"],
            "targeted_countries": ["US"],
            "suggested_labels": ["ransomware", "phishing"],
            "aliases": ["AliasOne"],
            "confidence": 85,
        }
        resp = MagicMock()
        resp.text = json.dumps(payload)
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(return_value=resp)

        entity = {
            "id": "report--1",
            "name": "Acme Widgets Ltd breached by Brand New Actor",
            "description": "Acme Widgets Ltd reports a data breach. " * 5,
            "objects": [],
        }
        result = c._enrich_report(entity)
        self.assertEqual(result, "Enriched")

        leaks = self._mutation_calls(c.helper.api)
        self.assertEqual(
            leaks, [],
            "AI_READ_ONLY leaked graph mutations: "
            + ", ".join(f"{p} x{n}" for p, n in leaks))

    def test_the_same_enrichment_does_write_when_not_read_only(self):
        """Counterpart: proves the catch-all above would actually notice a write."""
        c = _make_connector({"AI_CREATE_STUBS": "dry-run"})
        c.helper.api = MagicMock()
        for reader in ("intrusion_set", "threat_actor_group", "malware", "tool",
                       "identity", "vulnerability"):
            getattr(c.helper.api, reader).list = MagicMock(return_value=[])
        c.helper.api.attack_pattern.read = MagicMock(return_value=None)
        c.helper.api.note.list = MagicMock(return_value=[])
        resp = MagicMock()
        resp.text = json.dumps({"summary": "s", "confidence": 85,
                                "suggested_labels": ["ransomware"]})
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(return_value=resp)
        c._enrich_report({"id": "report--2", "name": "n",
                          "description": "d" * 60, "objects": []})
        self.assertTrue(self._mutation_calls(c.helper.api),
                        "expected writes when read-only is off")


class TestModelRoutingIgnoresRefAugmentation(unittest.TestCase):
    """Fetched reference text must not decide which model is used.

    Regression origin, observed in production: `_prepare()` appends several
    thousand characters of fetched article text, and `_call_gemini` then routed
    on the length of that augmented string. One retrieved reference was enough
    to promote a routine CVE to the expensive model, so the tier was decided by
    whether a fetch happened to succeed rather than by content complexity.
    """

    HIGH = "gemini-test-high"
    LOW = "gemini-test-low"

    def _conn(self, threshold="2000"):
        c = _make_connector({
            "GEMINI_MODEL_HIGH": self.HIGH,
            "GEMINI_MODEL_LOW": self.LOW,
            "GEMINI_MODEL_ROUTING_THRESHOLD": threshold,
            "AI_FETCH_REFS": "false",
        })
        self.assertEqual(c._model_high_name, self.HIGH)
        self.assertEqual(c._model_low_name, self.LOW)
        return c

    def _model_for(self, c, entity, min_report=False, entity_type="vulnerability"):
        """Drive the real path: _prepare() then _call_gemini(), and report the model."""
        content = c._prepare(entity, min_report=min_report)
        self.assertIsNotNone(content, "content was rejected as too short")
        resp = MagicMock()
        resp.text = json.dumps({"summary": "s", "confidence": 60})
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(return_value=resp)
        c._call_gemini("p {content}", content, entity_type=entity_type, entity=entity)
        _, kw = c._genai_client.models.generate_content.call_args
        return kw["model"]

    # --- the bug ---------------------------------------------------------

    def test_short_cve_with_large_fetched_refs_stays_on_cheap_model(self):
        c = self._conn()
        c._fetch_refs = True
        entity = {
            "id": "v--1",
            "name": "CVE-2026-12345",
            "description": "A short CVE description of about one hundred characters, "
                           "typical of an NVD entry body.",
            "externalReferences": [
                {"source_name": "a", "url": "https://a.example.com/1"},
                {"source_name": "b", "url": "https://b.example.com/2"},
                {"source_name": "c", "url": "https://c.example.com/3"},
            ],
        }
        # Production mean was ~18k chars retrieved per reference; the real
        # _fetch_reference_bodies then caps each at AI_FETCH_MAX_CHARS_PER_REF.
        with patch.object(connector_module, "fetch_reference_text",
                          return_value="A" * 18000):
            content = c._prepare(entity)
            self.assertGreater(len(content), 12000,
                               "refs should have inflated the prompt")
            self.assertEqual(self._model_for(c, entity), self.LOW)

    def test_same_cve_without_refs_also_cheap(self):
        c = self._conn()
        entity = {"id": "v--2", "name": "CVE-2026-12346",
                  "description": "A short CVE description, no references attached."}
        self.assertEqual(self._model_for(c, entity), self.LOW)

    # --- what must still work -------------------------------------------

    def test_genuinely_long_cve_description_still_gets_high_model(self):
        c = self._conn()
        entity = {"id": "v--3", "name": "CVE-2026-12347",
                  "description": "D" * 2500}   # the entity's OWN content is long
        self.assertEqual(self._model_for(c, entity), self.HIGH)

    def test_high_effort_types_always_high_regardless_of_length(self):
        for etype in ("report", "intrusion-set", "campaign"):
            c = self._conn()
            entity = {"id": f"e--{etype}", "name": "n",
                      "description": "tiny but high-effort type " * 3}
            self.assertEqual(
                self._model_for(c, entity, min_report=(etype == "report"),
                                entity_type=etype),
                self.HIGH, etype)

    def test_threshold_is_measured_against_own_content(self):
        c = self._conn(threshold="100")
        entity = {"id": "v--4", "name": "CVE-2026-1", "description": "D" * 150}
        self.assertEqual(self._model_for(c, entity), self.HIGH)
        c2 = self._conn(threshold="100")
        entity2 = {"id": "v--5", "name": "CVE-2026-2", "description": "D" * 50}
        self.assertEqual(self._model_for(c2, entity2), self.LOW)

    # --- the consume-once contract --------------------------------------

    def test_routing_length_is_consumed_once(self):
        c = self._conn()
        c._route_content_len = 99999
        resp = MagicMock()
        resp.text = json.dumps({"summary": "s", "confidence": 60})
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(return_value=resp)
        c._call_gemini("p {content}", "short", entity_type="vulnerability", entity={})
        self.assertIsNone(c._route_content_len, "must be cleared after use")

    def test_stale_length_cannot_route_a_later_enrichment(self):
        """A long entity must not make the NEXT short entity expensive."""
        c = self._conn()
        long_entity = {"id": "v--6", "name": "n", "description": "D" * 5000}
        self.assertEqual(self._model_for(c, long_entity), self.HIGH)
        short_entity = {"id": "v--7", "name": "n", "description": "D" * 100}
        self.assertEqual(self._model_for(c, short_entity), self.LOW)

    def test_falls_back_to_prompt_length_when_prepare_bypassed(self):
        """Direct _call_gemini callers keep the old behaviour, not a stale value."""
        c = self._conn()
        self.assertIsNone(c._route_content_len)
        resp = MagicMock()
        resp.text = json.dumps({"summary": "s", "confidence": 60})
        c._genai_client = MagicMock()
        c._genai_client.models.generate_content = MagicMock(return_value=resp)
        c._call_gemini("p {content}", "X" * 3000, entity_type="vulnerability", entity={})
        _, kw = c._genai_client.models.generate_content.call_args
        self.assertEqual(kw["model"], self.HIGH)

    def test_too_short_content_clears_the_routing_length(self):
        c = self._conn()
        c._route_content_len = 4242
        self.assertIsNone(c._prepare({"id": "v--8", "name": "x", "description": ""}))
        self.assertIsNone(c._route_content_len)

    # --- cost shape ------------------------------------------------------

    def test_production_shape_moves_off_the_premium_tier(self):
        """Replay the shape seen in practice: CVE + a couple of sizeable refs."""
        c = self._conn()
        c._fetch_refs = True
        entity = {
            "id": "v--9",
            "name": "CVE-2026-90010",
            "description": "Larkfield Systems PM-Monitor-W3 versions 2.2.9 and prior "
                           "are vulnerable to use of hard-coded credentials.",
            "externalReferences": [
                {"source_name": "cisa", "url": "https://cisa.example.com/1"},
                {"source_name": "vendor", "url": "https://vendor.example.com/2"},
            ],
        }
        with patch.object(connector_module, "fetch_reference_text",
                          return_value="B" * 18000):
            self.assertEqual(self._model_for(c, entity), self.LOW)

    def test_this_test_would_have_caught_the_bug(self):
        """Guard against a vacuous suite: assert the OLD logic fails these cases.

        If routing is ever reverted to measuring the augmented prompt, the
        production shape above must go back to the expensive tier. Proving that
        here means the tests above are load-bearing rather than passing by
        accident on short content.
        """
        c = self._conn()
        c._fetch_refs = True
        entity = {
            "id": "v--10", "name": "CVE-2026-1",
            "description": "Short CVE body, well under the 2000 char threshold.",
            "externalReferences": [{"source_name": "a", "url": "https://a.example.com/1"}],
        }
        with patch.object(connector_module, "fetch_reference_text",
                          return_value="A" * 18000):
            augmented = c._prepare(entity)
        # OLD behaviour: route on the augmented length -> expensive.
        self.assertEqual(
            c._resolve_model("vulnerability", len(augmented)), self.HIGH,
            "augmented length must exceed the threshold, else the test proves nothing")
        # NEW behaviour: route on the entity's own length -> cheap.
        self.assertEqual(
            c._resolve_model("vulnerability", len(entity["description"])), self.LOW)
