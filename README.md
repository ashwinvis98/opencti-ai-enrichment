# opencti-guarded-enrichment

An OpenCTI enrichment connector where the language model **proposes** entities and
relationships, and deterministic code **decides** what — if anything — reaches the
knowledge graph.

It reads a report with Gemini, connects it to the actors and malware families the
feed left out, and refuses the proposals that would do damage.

[![CI](https://github.com/ashwinvis98/opencti-guarded-enrichment/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

---

## The problem

Threat intelligence feeds are very good at the mechanical half of the job and
mostly decline the other half. Indicators arrive in bulk — hashes, domains,
addresses, all correctly typed and attached. What rarely arrives is the connection
between the report and the actor or malware family it is actually about.

You see it most clearly in reports named after the thing they are not linked to. A
write-up titled *DarkMe RAT*, carrying hundreds of indicators, connected to almost
nothing on the malware side. The feed did the part that is cheap to be right about
and skipped the part that needs someone to read prose and be willing to be wrong.

That is the gap this connector works on: turning reports that are rich in
indicators and poor in relationships into something that answers a question.

## Why this isn't just "ask the AI"

Gemini is genuinely good at this. It reads a vendor write-up and comes back with the
actor, the malware family, the techniques and the targeted sectors, as structured
fields. On reports that arrive nearly bare, that is the difference between a node
with some indicators hanging off it and something an analyst can use.

It is also entirely capable of quietly poisoning a knowledge graph. It proposes CVE
identifiers that exist at neither NVD nor CVE.org. It files the breached company as
the threat actor, because ransomware reporting names the victim more prominently
than the gang. It grows a curated sector taxonomy into hundreds of near-duplicates.

Both of those are true at once, and the reason the second one is dangerous is that
it looks exactly like the first. A hallucinated indicator is noise. A hallucinated
**relationship** is a false claim about the world, with a confidence score,
structurally indistinguishable from the true ones next to it — and nothing errors,
nothing fails a health check, and the object count goes up.

So the model proposes and deterministic code decides:

```
extraction (model) → critic (model, may only SUBTRACT)
   → shape guards → category guards → controlled vocabularies
   → dedup → grounding → relationship schema → creation mode
      → the graph
```

Every stage can only remove. There is no path where a model's confidence unlocks
something the guards refused. Reasoning about what this connector can do to your
graph means reading `enrichment/guards.py`, not predicting a model's behaviour.

The guardrails are not a brake on the value — they are what makes it deployable.
[OBSERVATIONS.md](OBSERVATIONS.md) has the real examples on both sides.

## The interesting part

Six times I built the ambitious version, watched how it behaved, and moved the
decision toward deterministic refusal. Six for six in the same direction. Two
capabilities were deleted rather than tuned:

- **Attack-Patterns** are lookup-only against MITRE ATT&CK. A locally invented
  technique id is not a technique, it is a string that pollutes the namespace. This
  restriction turned out to cost almost nothing, which surprised me — technique
  naming is the thing Gemini is most reliable at.
- **CVEs** are permanently lookup-only, with no environment variable to turn
  creation back on and a test asserting it stays gone. Proposed novel CVE
  identifiers existed at neither NVD nor CVE.org — and some arrived verbatim in the
  source feed's own report title, which means the groundedness gate *passes* them
  and structurally cannot help. A guard that cannot observe the failure is worse
  than no guard, because it justifies confidence.

The other four reversals — search grounding to fetching, parallel eval harnesses to
the connector owning its own accounting, name-shape heuristics to report-class
context, and an unsupervised critic to a subordinate one — are in
[DESIGN.md §6](DESIGN.md#6-six-reversals).

## Quick start

```bash
git clone https://github.com/ashwinvis98/opencti-guarded-enrichment
cd opencti-guarded-enrichment

# The test suite needs no credentials, no network and no OpenCTI.
pip install -r requirements-dev.txt
python -m pytest tests/ -q          # 374 passed
```

To run it against a platform:

```bash
cp .env.example .env
# fill in GEMINI_API_KEY, OPENCTI_TOKEN, CONNECTOR_ID
docker build -t opencti-guarded-enrichment .
docker run --env-file .env -v enrichment-state:/state opencti-guarded-enrichment
```

A **named volume** for `/state`, not a bind mount. The image creates `/state` owned
by the container's unprivileged user, and a named volume inherits that; a bind
mount onto a host directory owned by root leaves the container unable to write,
and the only symptom is an audit log that never appears.

`.env.example` ships the cautious defaults: `AI_READ_ONLY=true`,
`AI_CREATE_STUBS=dry-run`, `CONNECTOR_AUTO=false`. In that posture the connector
runs the entire pipeline — detection, critic, resolution, dedup — and logs exactly
what it would write, without writing it.

That is a starting point, not the destination. Sit there long enough to see how the
model behaves on *your* sources, then promote one entity category at a time as each
earns it. Some categories will earn it quickly; a couple never should. The evidence
is in `/state/ai_audit.log` and `ai_metrics.jsonl`, and
[OBSERVATIONS.md](OBSERVATIONS.md#how-to-tell-which-one-you-are-getting) describes
what to look for.

> Use a **read-only OpenCTI token** for that first period. It makes the guarantee
> structural rather than conditional on this code being correct.

## Layout

```
enrichment/
  prompts.py     typed extraction contracts, one per entity type, plus the critic
  names.py       normalisation and the three dedup key layers
  orgs.py        organisation keys, acronyms, title-derived canonicalisation
  grounding.py   deterministic source-evidence check (gates creation only)
  guards.py      the vocabularies and predicates that refuse bad entities
  relations.py   relationship type/direction against OpenCTI's own schema
  fetch.py       reference retrieval with SSRF protection
  vocab.py       STIX open-vocabulary normalisers
  metrics.py     per-category outcome matrix
  llm.py         the Gemini call — 15 lines, the only vendor SDK import
  connector.py   configuration, pipeline, decision funnel
tests/           374 tests, concentrated on the guard layer
tools/           offline labelling and scoring of recorded outcomes
docs/            CONFIGURATION.md
```

Start with `guards.py`. That is where the interesting failures live.

15 lines of model-calling code against 4,385 lines of everything else is the
honest summary of this project: almost none of it is about calling a model.

## Documentation

| | |
| --- | --- |
| [OBSERVATIONS.md](OBSERVATIONS.md) | Where Gemini worked well and where it went wrong, with real examples on both sides. Why "just enrich it with Gemini" is the wrong instinct, and how to roll this out without finding out the hard way. |
| [DESIGN.md](DESIGN.md) | Why the problem exists, the industry context, the guard methodology, the six reversals, the self-feedback loop, and the one-person-threat-team argument. |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | All 40 environment variables, and why each default is the cautious one. |

## Scope and honesty

**What it handles.** Report, Intrusion-Set, Threat-Actor-Group, Malware, Campaign,
Vulnerability. Each has its own extraction contract and relationship rules.

**What it is not.**

- Not a general AI-for-CTI platform. One connector, one provider, six entity types.
- **Only Gemini has been run.** `llm.py` isolates the SDK, which would make another
  provider a contained change, but I have not done it. There is deliberately no
  provider abstraction — an interface with one implementation advertises
  portability it has not demonstrated.
- Not autonomous, and not trying to be. Which categories are allowed to write is a
  human decision, made per category, informed by what the logs show.
- Not a fix for attribution gaps. Where the source material does not attribute, the
  model generally does not either. There is a real example of that in
  [OBSERVATIONS.md](OBSERVATIONS.md#it-declines-exactly-where-the-feed-declines).
- The evaluation corpus is not shippable. `tools/` is published as methodology; the
  data is real breach reporting about real organisations. There is no synthetic
  substitute here, because a fabricated corpus produces something that looks like
  evidence and is not.
- Guards are code and code is wrong. The mitigations are cautious defaults,
  reversibility (everything created carries `ai-suggested`, so undoing it is one
  query), and 374 tests — not a belief that the guard layer is correct.
- The confidence score is the model's own self-report, and it comes back high on
  nearly every document regardless of how hard the document was. Treat it as
  provenance, not quality. It is the weakest part of the design as it stands, and
  [OBSERVATIONS.md](OBSERVATIONS.md#confidence-that-means-nothing) says so.

## Status

Working, and run against a live OSINT feed. The extraction does what it is meant
to: it reads reports the feed left unconnected and produces the actor, malware
family, technique and sector links that were missing.

The guard layer is where most of the engineering went, and it earned it — the
things it refuses are things I watched the model get wrong, not hypotheticals. Two
entity categories had their creation capability removed entirely rather than tuned.
[OBSERVATIONS.md](OBSERVATIONS.md) has the specifics, including the cases where
Gemini was excellent and the cases where it would have done real damage.

## Licence

[Apache 2.0](LICENSE)
