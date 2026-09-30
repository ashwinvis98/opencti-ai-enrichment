# Configuration reference

Every setting is an environment variable. There is no config file. The connector
reads all 40 of them once, at construction, and validates them there — so a bad
value is reported at startup rather than discovered in the middle of a run.

Three variables are required and the process exits if any is missing. Everything
else has a default, and **the defaults are the safe ones**: as shipped in
[`.env.example`](../.env.example), the connector performs the complete analysis
and writes nothing to the knowledge graph.

Jump to: [Required](#required) · [OpenCTI](#opencti-connection) ·
[Model](#model-selection-and-routing) · [Write guardrails](#write-guardrails) ·
[Output](#what-gets-written) · [Confidence](#confidence) · [Critic](#critic-pass) ·
[Reference fetching](#external-reference-fetching) · [Pacing](#pacing) ·
[Audit](#audit-trail) · [Invalid values](#how-invalid-values-are-handled)

---

## Required

Absent or whitespace-only means `logging.critical` followed by `sys.exit(1)`. The
connector does not start in a degraded mode, because every degraded mode here
would involve writing to a graph with a misconfigured guard.

| Variable | Notes |
| --- | --- |
| `GEMINI_API_KEY` | Google AI Studio key. Never commit it; `.env` is git-ignored. |
| `OPENCTI_TOKEN` | OpenCTI API token. With `AI_READ_ONLY=true` a read-only token is sufficient and is what you should use — it makes the guarantee structural instead of conditional on this code being correct. |
| `CONNECTOR_ID` | A UUIDv4 you generate once and keep. It is the connector's stable identity in OpenCTI across restarts. `python -c "import uuid; print(uuid.uuid4())"` |

`AI_IDEMPOTENCY_LABEL` is a fourth exit-on-failure case, but only if you
explicitly set it to an empty or whitespace-only string. It defaults to
`ai-enriched`. An empty idempotency marker would silently disable re-run
protection, which is worse than not starting.

---

## OpenCTI connection

| Variable | Default | Notes |
| --- | --- | --- |
| `OPENCTI_URL` | `http://localhost:8080` | |
| `CONNECTOR_NAME` | `AI Enrichment (Gemini)` | Display name in the OpenCTI connector list. |
| `CONNECTOR_AUTO` | `true` | `true` lets OpenCTI invoke the connector automatically on in-scope entities. Set it to `false` to start: automatic invocation across a live feed is how you discover your model rate limits the expensive way. |
| `CONNECTOR_LOG_LEVEL` | `info` | Passed through to pycti. |

The enrichment scope is fixed in code, not configurable:

```
Report, Intrusion-Set, Threat-Actor-Group, Malware, Campaign, Vulnerability
```

Each of those has its own handler with its own extraction contract and its own
relationship rules. A scope entry without a handler would be a silent no-op, so
the list is not something you widen from the outside.

---

## Model selection and routing

| Variable | Default | Notes |
| --- | --- | --- |
| `GEMINI_MODEL_HIGH` | `gemini-3.6-flash` | Used for Reports, Intrusion-Sets and Campaigns, and for any entity whose own content exceeds the routing threshold. |
| `GEMINI_MODEL` | — | Fallback for `GEMINI_MODEL_HIGH` if that is unset. Kept for older deployments. |
| `GEMINI_MODEL_LOW` | value of `GEMINI_MODEL_HIGH` | Used for everything else, and for every critic pass. |
| `GEMINI_MODEL_ROUTING_THRESHOLD` | `2000` | Characters. Minimum `1`. |
| `GEMINI_ENABLE_SEARCH` | `auto` | `auto` \| `always` \| `never`. See below. |
| `GEMINI_SEARCH_CONTENT_FLOOR` | `500` | In `auto` mode, content shorter than this many characters counts as thin and triggers search. |

Routing decides on the entity's **own** content length, measured before external
references are appended. Routing on the augmented length would mean a short
Malware entity gets promoted to the expensive model purely because it happened to
link to a long blog post — the model tier should track how hard the *entity* is,
not how much text the fetcher managed to collect.

`GEMINI_ENABLE_SEARCH` modes:

- **`auto`** — search when it plausibly adds value (external references present,
  or the content is thin), skip it for rich self-contained content.
- **`always`** / `true` / `1` / `yes` — always ground on Google Search.
- **`never`** / `false` / `0` / `no` — never search. Recommended, and what
  `.env.example` ships.

Two things make `never` the better default. The Gemini API does not permit search
grounding together with forced JSON mode, so enabling search means giving up the
strongest parse guarantee available and falling back to prompt instructions plus
fence-stripping. And search grounding draws on a separate, tightly-capped quota.
Fetching the referenced article yourself (`AI_FETCH_REFS`) costs no model quota
and is deterministic — you control exactly what the model sees. That tradeoff is
discussed at length in [DESIGN.md](../DESIGN.md).

---

## Write guardrails

This is the part of the configuration that matters. Everything here defaults to
the setting that writes less.

| Variable | Default | Notes |
| --- | --- | --- |
| `AI_READ_ONLY` | `false` | **`.env.example` ships `true`.** When true, the connector runs detection, the critic, entity resolution, dedup and metrics in full, and writes nothing to the graph: no notes, no labels, no fields, no relationships, no entities. |
| `AI_CREATE_STUBS` | `false` | Tri-state: `off` \| `dry-run` \| `on`. Global default for entity creation. |
| `AI_CREATE_ACTORS` | inherits | Per-category override, same tri-state. |
| `AI_CREATE_MALWARE` | inherits | |
| `AI_CREATE_TOOLS` | inherits | |
| `AI_CREATE_VICTIMS` | inherits | |
| `AI_CREATE_SECTORS` | `false` | Separate switch; lookup-only against the curated sector vocabulary by default. |
| `AI_REQUIRE_GROUNDING` | `true` | Refuse to create an entity whose name is not traceable to the analysed source text. |

### The tri-state

| Value | Behaviour |
| --- | --- |
| `off` (also `false`, or anything unrecognised) | Never create. Link only to entities that already exist in the knowledge base. |
| `dry-run` (also `dryrun`, `dry_run`, `dry`) | Do not create, but log and count precisely what *would* have been created. |
| `on` (also `true`, `1`, `yes`) | Create the missing entity, tagged with `AI_REVIEW_LABEL`. |

`dry-run` is the important value, and it is the reason the tri-state exists
rather than a boolean. A boolean forces a choice between no evidence and live
writes. `dry-run` gives you the full would-create ledger — name, category,
confidence, which gate it passed, what it would have linked to — at zero risk.
You read weeks of that before promoting anything.

### Per-category promotion

Per-category overrides exist because precision is not uniform across entity
types. Actors, malware, tools and victims each have their own error mode, and
they do not clear a quality bar at the same time. The override lets you enable
the one category that has earned it while the noisier ones stay in `dry-run`.
Unset means inherit the global.

`AI_READ_ONLY=true` overrides all of this. Any category set to `on` is downgraded
to `dry-run` rather than to `off` — silently setting it to `off` would stop the
would-create accounting too, and then a read-only run would no longer tell you
what the connector wanted to do.

### The two categories with no switch at all

**Attack-Patterns** and **CVEs** are permanently lookup-only. There is no
environment variable that turns creation on for them, by design:

- Attack-Patterns belong to MITRE ATT&CK. A locally invented technique id is not
  an ATT&CK technique, it is a string that looks like one, and it pollutes every
  query that assumes the ATT&CK namespace means something.
- CVEs belong to NVD. CVE creation was removed after watching it run, not before:
  proposed novel CVE identifiers regularly turned out not to exist at NVD *or*
  CVE.org, and some arrived verbatim in the source feed's own report
  title — which means the groundedness gate passes them and cannot help. A guard
  that structurally cannot see the error is not a guard.

`AI_CREATE_SECTORS` is a separate switch rather than a member of the tri-state
family because the failure mode is different. Sector creation does not invent a
fake fact; it fragments a working taxonomy. An unchecked feed turns a couple of
dozen canonical sectors into several hundred near-duplicates, and every
sector-scoped query silently gets less complete from then on. The default links a
detected sector to an existing canonical sector by name or alias and creates
nothing.

### Grounding

`AI_REQUIRE_GROUNDING` is a deterministic string check against the normalised
source text, not another model call. It gates **creation** only; linking to an
entity that already exists is unaffected, because an existing entity is already
somebody's asserted fact and the connector is not the thing that vouched for it.

Leave it on. It is the cheapest guard in the system and it catches the specific
failure that matters most: a plausible-sounding name the model produced from
prior knowledge rather than from the document in front of it.

---

## What gets written

| Variable | Default | Range | Notes |
| --- | --- | --- | --- |
| `AI_CONTENT_LIMIT` | `8000` | 1–1,000,000 | Characters of entity content sent to the model. |
| `AI_ENRICH_FIELDS` | `true` | | Structured field enrichment: motivation, malware types, CVSS, and similar. |
| `AI_APPLY_SUGGESTED_LABELS` | `true` | | |
| `AI_MAX_LABELS` | `10` | 0–25 | Clamped, not rejected. |
| `AI_IDEMPOTENCY_LABEL` | `ai-enriched` | | Applied to entities already enriched. This is how a re-run knows to skip. |
| `AI_REVIEW_LABEL` | `ai-suggested` | | Applied to everything the connector created rather than found. |
| `AI_ALIAS_WRITEBACK` | `false` | | Write discovered aliases back onto the entity being enriched. |

Both labels are reserved: the connector will never re-apply either of them as a
model-*suggested* label. Without that, the model could propose `ai-enriched` as a
descriptive tag on an entity the connector had not enriched, and the idempotency
marker would stop meaning anything.

`AI_REVIEW_LABEL` is the reversibility guarantee. Everything the AI introduced
carries it, so the full set of AI-originated entities is one query, and undoing
the experiment is one bulk operation rather than an archaeology project.

`AI_ALIAS_WRITEBACK` is the self-improving path: aliases the model discovers get
added to the entity, so the next run's name matching is better than this run's.
It is off by default because unlike everything else in this section it modifies a
pre-existing entity that nobody asked the connector to touch.

---

## Confidence

| Variable | Default | Range | Notes |
| --- | --- | --- | --- |
| `AI_CONFIDENCE_DECAY_ENABLED` | `true` | | Decay confidence with the age of the source material. |
| `AI_CONFIDENCE_CALIBRATION_OFFSET` | `0` | -50–50 | Flat correction applied to model confidence. Clamped. |
| `AI_MIN_CVSS` | `0` | 0–10 | Skip auto-enrichment of standalone Vulnerabilities below this CVSS base score. `0` disables the gate. |

Set the calibration offset only with a measurement in hand. It is a blunt
instrument: it shifts every score by the same amount, so it corrects a systematic
bias and makes everything else worse. If the model is overconfident about one
category specifically, the per-category creation mode is the right control.

`AI_MIN_CVSS` exists because auto-summarising every CVE that arrives from NVD is
a lot of model spend for very little graph value. Most standalone CVEs are never
going to be connected to anything.

---

## Critic pass

| Variable | Default | Notes |
| --- | --- | --- |
| `AI_CRITIC_ENABLED` | `false` | A second, cheap `GEMINI_MODEL_LOW` call with no search reviews the extracted entities and flags mis-typed, generic, junk and victim-as-actor items before anything is linked or created. |

Off by default because it doubles the call count per enrichment.

The critic is advisory to a deterministic gate, not an authority. It can *drop*
or *reclassify* a proposal; it cannot approve one that the deterministic guards
reject. That ordering is deliberate and is the subject of one of the reversals
described in [DESIGN.md](../DESIGN.md) — an LLM reviewing an LLM produces a
confident second opinion, which is not the same thing as a check.

---

## External reference fetching

| Variable | Default | Range | Notes |
| --- | --- | --- | --- |
| `AI_FETCH_REFS` | `true` | | Fetch the linked source article and give the model its text. |
| `AI_FETCH_TIMEOUT` | `10` | 1–60 | Seconds, per reference. |
| `AI_FETCH_MAX_REFS` | `3` | 0–10 | `0` disables fetching as effectively as `AI_FETCH_REFS=false`. |
| `AI_FETCH_MAX_CHARS_PER_REF` | `4000` | 200–40,000 | Characters kept from each article after HTML-to-text. |
| `AI_FETCH_MAX_BYTES` | `400000` | 10,000–5,000,000 | Hard cap on bytes read from a single response. |

Fetching replaced Google Search grounding. Grounding consumed a separate,
tightly-capped quota and left the connector unable to say what the model had
actually read; fetching costs no model quota, is deterministic, and makes the
prompt reproducible. Auth-gated portals are detected and skipped rather than
fed to the model as a login page.

The fetcher validates every URL against SSRF before connecting: scheme, resolved
address, private and link-local ranges, and redirect targets. It runs inside your
infrastructure against URLs that arrived from a feed, which is exactly the
position an SSRF primitive wants to be in. `AI_FETCH_MAX_BYTES` is part of the
same posture — a response is a hostile-controlled stream and needs a hard stop
independent of any `Content-Length` it claims.

Results are cached per enrichment, so several references pointing at the same
article cost one fetch.

---

## Pacing

| Variable | Default | Notes |
| --- | --- | --- |
| `AI_MAX_RPM` | `0` | Client-side requests-per-minute cap. `0` means no pacing. |

Gemini enforces per-minute and per-day quotas server-side. Without client pacing,
a busy feed produces 429 storms in which every rejected call costs a long backoff
sleep, and effective throughput collapses to well below the quota you were trying
to use. Setting `AI_MAX_RPM` just under your actual quota means you stay under it
instead of repeatedly rediscovering it. The interval is enforced under a lock, so
it holds across worker threads.

---

## Audit trail

| Variable | Default | Range | Notes |
| --- | --- | --- | --- |
| `AI_AUDIT_LOG` | — | | Path to mirror every log line to. Unset disables the durable trail. |
| `AI_AUDIT_LOG_MAX_MB` | `64` | 1–4096 | Rotation size. |

Container logs die with the container and metrics live in memory, so a redeploy
erases all evidence of how the connector behaved — which is fatal to an
evaluation that runs for weeks. Point `AI_AUDIT_LOG` at a bind-mounted path and
every line is mirrored there with rotation, and each metrics summary is appended
as a JSON line to `ai_metrics.jsonl` in the same directory. That file is the input
to any analysis of behaviour over time.

The file handler is attached **after** `OpenCTIConnectorHelper` is constructed.
pycti reconfigures the logging stack during its own init and discards handlers
attached before it. The symptom, if you get this wrong, is an audit file that gets
created and then never written to.

> The audit log contains real entity names from your graph. It is git-ignored for
> that reason. Treat it as graph data, not as logs.

---

## How invalid values are handled

Numeric settings fall into two groups, and the difference is intentional.

**Clamped** — a value outside the range is silently pulled to the nearest bound:
`AI_MAX_LABELS`, `AI_CONFIDENCE_CALIBRATION_OFFSET`, `AI_MIN_CVSS`,
`GEMINI_SEARCH_CONTENT_FLOOR`, `AI_MAX_RPM`. For these, the out-of-range intent
is unambiguous — `AI_MAX_LABELS=100` means "as many as you'll give me".

**Warn and default** — a value that is non-numeric or out of range is rejected,
logged at `WARNING`, and replaced by the documented default:
`AI_CONTENT_LIMIT`, `GEMINI_MODEL_ROUTING_THRESHOLD`, `AI_AUDIT_LOG_MAX_MB`,
and all five `AI_FETCH_*` numerics. For these, clamping would hide a typo that
changes behaviour substantially.

Either way a bad value produces a log line at startup, never an exception
mid-enrichment.

### Boolean parsing is not uniform, and you should know where

Most booleans accept `true`, `1`, `yes`, `on`. Three accept only
`true`, `1`, `yes` — `on` does not work for them:

- `AI_CONFIDENCE_DECAY_ENABLED`
- `AI_APPLY_SUGGESTED_LABELS`
- `AI_MAX_LABELS` (not a boolean, listed here only because it sits in the same block)

`CONNECTOR_AUTO` is stricter still: it accepts exactly `true` or `false`, and
anything else logs a warning and defaults to `true`.

This inconsistency is an accretion artefact, documented rather than quietly
fixed, because normalising it now would change the behaviour of any existing
deployment that happens to be relying on the current parsing. Use `true` and
`false` everywhere and none of it affects you.

---

## Recommended starting posture

```dotenv
AI_READ_ONLY=true
AI_CREATE_STUBS=dry-run
AI_REQUIRE_GROUNDING=true
GEMINI_ENABLE_SEARCH=never
AI_FETCH_REFS=true
CONNECTOR_AUTO=false
AI_AUDIT_LOG=/state/ai_audit.log
```

Run that against real traffic for long enough to accumulate a would-create ledger
you can actually judge. Then promote one category at a time, as each earns it. The
reasoning behind that sequence is in [DESIGN.md](../DESIGN.md), and
[OBSERVATIONS.md](../OBSERVATIONS.md) describes what the model got right and wrong
when it was applied.
