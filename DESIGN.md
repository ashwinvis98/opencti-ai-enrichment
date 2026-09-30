# Design

This document is about the reasoning, not the API. If you want the knobs, read
[docs/CONFIGURATION.md](docs/CONFIGURATION.md). If you want the concrete examples
of where the model shone and where it failed, read
[OBSERVATIONS.md](OBSERVATIONS.md).

The one-line version: **the language model proposes, deterministic code decides.**
Everything below is either an argument for that split or a record of a time running
the thing forced me to move a decision from one side of it to the other.

---

## Contents

1. [The problem](#1-the-problem)
2. [Why the problem exists](#2-why-the-problem-exists)
3. [Why AI, and why now](#3-why-ai-and-why-now)
4. [The design position: propose vs decide](#4-the-design-position-propose-vs-decide)
5. [The guard layer](#5-the-guard-layer)
6. [Six reversals](#6-six-reversals)
7. [The self-feedback loop](#7-the-self-feedback-loop)
8. [The one-person threat team](#8-the-one-person-threat-team)
9. [What this does not do](#9-what-this-does-not-do)

---

## 1. The problem

Threat intelligence platforms fill up with reports that are not connected to
anything.

Spend any time with an OSINT feed and the pattern is hard to miss. A report comes
in carrying a wall of indicators — hashes, domains, addresses, each correctly typed
and attached to the report. What it does not carry is a link to the actor or the
malware family the report is about. The mechanical work is done impeccably; the
judgement work is simply absent.

It is most obvious on the reports named after the thing they are not linked to. A
write-up titled *DarkMe RAT*, hundreds of indicators deep, connected to barely
anything on the malware side. *PureRAT and PureLogs Campaign Targeting Japanese
Organizations*, same story. The information is right there in the title, and the
graph does not have it.

Two things are worth separating when you look at a report's contents. Call the
first **IOC plumbing**: indicators, file hashes, domains, addresses, and the
`indicates` relationships attaching them. Call the second **graph-building**:
Intrusion-Set, Malware, Tool, Attack-Pattern, Sector, Country, Vulnerability — the
objects that answer a question someone actually asks. Feeds deliver the first in
bulk and the second sparsely, and the gap between the two is not subtle.

One nuance that stops this being a complaint about feeds: Attack-Patterns are
usually the *healthiest* graph category, because OTX ships ATT&CK ids natively as a
structured field. Where the feed has a machine-readable field it does fine. The gap
sits precisely where the answer requires reading prose and being willing to be
wrong — which is to say, where judgement starts.

That gap is what this connector is for. Not "AI is good at security" — one
specific, unglamorous hole in a specific pipeline.

---

## 2. Why the problem exists

The gap is not a bug in OTX. It follows from three structural facts.

**Feeds are optimised for the thing that is cheap to be right about.** An
indicator is a string with a type. Extracting it is mechanical, verifying it is
mechanical, and being wrong about it is cheap — a stale hash is noise, not a false
claim about the world. Saying "this campaign is Konni" is an assertion about
attribution. It requires reading the report, knowing the naming landscape, and
accepting that you can be wrong in a way that misleads people. Feeds ship the
first kind at enormous volume and largely decline the second, and that is a
defensible engineering choice on their part.

**The consumer inherits the judgement work and cannot staff it.** Somebody has to
read the report and decide it is about Konni. In most organisations that somebody
is one analyst with a queue, or nobody. The work does not scale with headcount
because it is not parallelisable in the way ticket triage is: the value comes from
holding the whole naming landscape in your head at once.

**The cost of the gap is invisible.** A report with hundreds of indicators and no
actor link looks productive. Dashboards count objects, and it has plenty. What it
cannot do is answer "what do we know about Konni" — the query returns the reports
somebody manually linked, and silently omits the rest. Nobody gets paged for a
query that returns an incomplete answer confidently. So the debt accumulates for
years, and the first symptom is a decision made on a partial graph.

Put those together and you get the actual shape of the problem: **a large,
never-ending volume of low-difficulty-per-item judgement work, whose absence is
silent.** That is an unusually good fit for automation and an unusually bad fit
for automation that can be confidently wrong — which is the tension the rest of
this document is about.

---

## 3. Why AI, and why now

Two things changed, and it is worth being precise about which one is the argument.

### The capability argument is about extraction, not reasoning

Language models became reliable at a narrow thing: reading a page of prose and
returning structured fields that conform to a schema. Not "understanding threat
intelligence" — extracting the malware family name from a paragraph that mentions
it three different ways, and putting it in the `malware_families` array. That is
the operation the gap in §1 actually needs, and it is close to the easiest thing
a modern model does.

Everything hard is downstream of extraction: is this name the same entity as one
we already have, is this a threat actor or the company that got breached, does
this technique id exist. Those are the questions this codebase answers in Python.

### The market argument

The industry has been repricing exactly this kind of work, publicly and
expensively.

Google announced its acquisition of Mandiant in March 2022 for **$5.4 billion** in
an all-cash deal at $23.00 per share — roughly a 57% premium to the
pre-announcement price — and [completed it that
September](https://cloud.google.com/blog/products/identity-security/google-completes-acquisition-of-mandiant),
folding Mandiant into Google Cloud. Three years later Google [signed an agreement
to acquire the cloud security company Wiz for $32
billion](https://www.prnewswire.com/news-releases/google-announces-agreement-to-acquire-wiz-302404500.html),
announced March 2025 and closed in March 2026: its largest acquisition ever by a
wide margin, more than double Motorola Mobility at $12.5 billion in 2012.

You can read the strategy several ways, but the direction is not ambiguous.
Security expertise is being bought by the companies that own the compute and the
models, at prices that imply it is a platform capability rather than a product
line. The expertise is converging with the inference.

### The adversary already made the argument for me

This part I did not go looking for. Working through recent feed content for the
examples in this repo, a noticeable share of it turned out to be reporting on
adversaries using AI. Three that came up without my selecting for the theme:

- *Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix*
  ([Huntress](https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat))
- *The Closed Quorum: first reported autonomous AI C2 implant*
  ([Cisco Talos](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/))
- *New RemControl Android Banking Trojan ... AI-Built Phishing*
  ([Cyber Press](https://cyberpress.org/remcontrol-trojan-steals-banking-pins/))

An autonomous AI C2 implant, custom GPTs used for delivery, AI-built phishing. The
offensive side is not waiting for a governance review. That does not make defensive
AI automatically correct — it makes the *absence* of it a choice with a cost.

### Why this does not license "let the AI do it"

The honest version of the AI argument is narrower than the marketing version. The
model is good at reading. It is confidently unreliable at deciding, and the
failure mode is the worst possible one for a knowledge graph: fluent, plausible,
well-formed output that is wrong. A hallucinated indicator is noise. A
hallucinated **relationship** is a false fact about the world, sitting in the
graph with a confidence score, indistinguishable from the real ones, and it will
be cited.

So: the capability is real, the incentive is real, and neither of them earns the
model write access to the graph. That is the next section.

---

## 4. The design position: propose vs decide

Every entity or relationship the model produces passes through a funnel. The
model's output is an input to the funnel, never a decision by it.

```
  entity content (+ fetched reference text)
            │
            ▼
   ┌──────────────────┐
   │ typed extraction │   prompts.py — one contract per entity type,
   │    (the model)   │   forced JSON where the API permits it
   └────────┬─────────┘
            │  proposals: names, types, relationships, confidence
            ▼
   ┌──────────────────┐
   │   critic pass    │   optional second model call: may DROP or
   │   (the model)    │   RECLASSIFY a proposal. May not approve one.
   └────────┬─────────┘
            ▼
  ═══════ everything below this line is deterministic Python ═══════
            │
   ┌────────┴─────────┐
   │  shape guards    │   guards.py — is this a name at all?
   └────────┬─────────┘   junk, generic, collective descriptor
   ┌────────┴─────────┐
   │ category guards  │   is this the KIND of thing it claims?
   └────────┬─────────┘   legit software, infra, security product,
            │             miner, leak-site operator, victim-vs-actor
   ┌────────┴─────────┐
   │   vocabularies   │   MITRE ATT&CK ids, CVE format, curated
   └────────┬─────────┘   sectors, STIX open-vocabs
   ┌────────┴─────────┐
   │      dedup       │   names.py / orgs.py — three key layers
   └────────┬─────────┘
   ┌────────┴─────────┐
   │    grounding     │   grounding.py — is the name traceable to
   └────────┬─────────┘   the source text? (gates CREATION only)
   ┌────────┴─────────┐
   │ relation schema  │   relations.py — does OpenCTI permit this
   └────────┬─────────┘   type/direction between these two types?
   ┌────────┴─────────┐
   │  creation mode   │   off / dry-run / on, per category
   └────────┬─────────┘
            ▼
      the knowledge graph
```

Three properties of that diagram are the actual design.

**The critic is subordinate, not authoritative.** It can remove a proposal. It
cannot promote one past a deterministic guard. An LLM reviewing an LLM produces a
confident second opinion, and a second opinion drawn from the same distribution as
the first is not an independent check — it is correlated error with extra steps.
Ordering it *before* the deterministic layer, and giving it only the power to
subtract, is what makes it useful rather than decorative.

**Every gate can only subtract.** There is no path where a model's confidence
score unlocks something the guards refused. This means the guarantee is
structural. Reasoning about what the connector can do to the graph requires
reading the guard layer, not predicting a model's behaviour.

**Write access is earned per category, not granted once.** `AI_READ_ONLY=true` and
`AI_CREATE_STUBS=dry-run` ship as the defaults so that a new deployment runs the
entire funnel, logs exactly what it would write, and lets you see how the model
behaves on *your* sources before it touches anything. Then categories get promoted
individually as they earn it. Some earn it quickly. A couple never should, and the
mechanism for that is described in §6 — the point is that the decision is made per
category with evidence in hand, rather than as one up-front act of faith.

### Reversibility, since guards fail

Guards are code, and code is wrong sometimes. So everything the connector creates
carries `AI_REVIEW_LABEL` (`ai-suggested` by default). The complete set of
AI-originated entities is one label query, and undoing the experiment is a bulk
operation. `AI_IDEMPOTENCY_LABEL` (`ai-enriched`) marks what has already been
processed, so a re-run is a no-op rather than a second opinion layered on the
first. Both labels are reserved — the model is never allowed to *suggest* either
of them, because a model-applied `ai-enriched` on an unprocessed entity would
quietly destroy the meaning of the marker.

---

## 5. The guard layer

`guards.py` is the file to read. Its predicates are all shaped the same way:
deterministic, name-in/bool-out, individually testable, and each one exists
because of a specific class of wrong answer.

**Is this a name at all?** `is_junk_name` catches truncation, punctuation
wreckage, and fragments. `is_generic_entity_name` catches
`is_generic_entity_name("the threat actor")` — a description that arrived where a
name belonged. `is_collective_descriptor` catches "several Chinese APT groups",
which is a true statement and not an entity.

**Is this the kind of thing it claims to be?** This is where most real false
positives live, because the model's type assignment is much weaker than its
extraction. `is_known_legit_software` and `is_infra_software` stop Microsoft
Exchange being filed as malware because a report about exploiting Exchange
mentions it forty times. `is_security_product` stops the defender's own EDR being
recorded as a tool used by the adversary. `is_miner` and `is_tool_noise` handle
dual-use software and the long tail of utilities that appear in every report.
`is_consumer_software_noise` handles the browsers and PDF readers that get named
as infection vectors.

**Is this the adversary or the victim?** `has_victim_context` and
`is_leak_site_operator` exist because of the single most damaging error the
pipeline can make. Ransomware reporting names the breached company more often and
more prominently than it names the gang. A naive extractor confidently files the
victim as the threat actor, and now the graph asserts that a hospital attacked
somebody. `is_non_actor_name` and `is_adversary_brand_name` work the same seam
from the other side, using company-name markers and adversary-brand markers
respectively. `_name_regex_forms` generates the variant spellings a name appears
in, because the evidence for "this is a victim" is usually a sentence near a
*different* form of the name than the one extracted.

**Does the identifier exist?** `is_valid_mitre_id` and `is_valid_cve` check format
against the real namespaces, and for these two categories format-checking is not
the end of it — see the reversals below.

There are 374 tests across the guard layer and the pipeline around it, and none
that assert anything about the model's output quality. That is the deliberate
part: the model is not the component that needs regression protection, because the
model is not the component that decides. What needs protection is every rule that
was added because something went wrong once.

---

## 6. Six reversals

This section is the actual methodology. Each of these is a place where I built the
ambitious thing, watched how it behaved on real content, and moved the decision
toward the deterministic side. The pattern is the point — running it moved the
boundary in the same direction every single time, and I would not have predicted
that from the outset.

### 6.1 Attack-Patterns: creation → lookup-only

**What I built.** The earliest version of this work — a small proof of concept —
created Attack-Pattern entities from techniques the model named. That behaviour was
inherited when the connector was built out properly, and carried forward as an
explicit requirement rather than questioned.

**What went wrong.** The model names techniques confidently and in ATT&CK's own
register. Some of those names do not correspond to an ATT&CK technique. The result
is an entity in the ATT&CK namespace that ATT&CK has never heard of, with no
description and no relationships — hollow, and worse than absent, because every
subsequent query that assumes the namespace means something now returns it.

**The reversal.** Attack-Patterns are lookup-only against the imported ATT&CK
catalogue. Named technique not found, no entity. There is no environment variable
to turn this back on.

**What it cost, which surprised me.** I assumed lookup-only would throw away a
meaningful amount of good output here. It throws away almost nothing — technique
naming turns out to be the thing Gemini is most dependable at, and the techniques
it names overwhelmingly resolve to real, already-imported ATT&CK entities. The
restriction that felt most severe when I wrote it is the cheapest one in the
system. Worth knowing, because the intuition that every guard trades away recall is
usually just untested.

**The general lesson.** When an authoritative source for a namespace exists, the
only correct operations are *look up* and *fail*. "Create if missing" is a
statement that you are now a co-author of somebody else's taxonomy.

### 6.2 CVEs: creation → permanently lookup-only, after watching it run

**What I built.** CVE creation behind the same dedup and grounding gates as
everything else, with `is_valid_cve` format validation in front. Format-valid, from
the source text, gated — this seemed sufficient.

**What went wrong.** In dry-run, a substantial share of proposed novel CVE
identifiers turned out not to exist at NVD *or* CVE.org. And a subset arrived
verbatim in the source feed's own report title — which means they are present in
the analysed text, which means **the groundedness gate passes them**. The guard
was structurally blind to the error, not merely weak against it.

**The reversal.** `cve` was removed from `_CREATE_ENV` entirely. Not set to `off`
— removed, so there is no variable to set. A test asserts its absence
(`assertNotIn("cve", _CREATE_ENV)`) and another asserts the creation method no
longer exists, so the capability cannot be reintroduced by accident.

**The general lesson.** This is the most useful thing I learned on the project. A
guard that cannot observe the failure is not a weak guard, it is a *false* guard,
and shipping one is worse than shipping none because it justifies confidence.
Grounding answers "is this name in the document". It does not answer "is this a
real CVE", and no amount of tuning makes it answer that. The only fix was to
remove the capability the guard was supposed to protect.

Note also that this reversal was only possible because dry-run mode existed. With
a boolean create flag, the choice would have been no evidence or live writes, and
the fake CVEs would have been in the graph before anyone knew to look.

### 6.3 Google Search grounding → fetching the reference myself

**What I built.** Reference URLs pasted into the prompt, with Gemini's Search
grounding enabled so the model could go read them.

**What went wrong.** Three things. The grounding quota is separate from and much
tighter than the token quota, so it became the binding constraint. The Gemini API
does not allow search grounding together with forced JSON mode, so using it meant
giving up the strongest parse guarantee available and falling back to prompt
instructions plus fence-stripping. And most importantly, I could not say what the
model had read — which makes the output unreproducible and the errors
undiagnosable.

**The reversal.** `fetch.py` retrieves the article, converts it to text, truncates
it, and puts it in the prompt. No model quota, deterministic, and the exact input
is knowable. `GEMINI_ENABLE_SEARCH=never` is the recommended setting.

This moved an SSRF surface inside the trust boundary, which I had to handle rather
than note: the connector now makes outbound requests to URLs that arrived from an
untrusted feed. Scheme, resolved address, private and link-local ranges, and
redirect targets are all validated, and `AI_FETCH_MAX_BYTES` caps the read
independently of any `Content-Length` the response claims. The test suite asserts
RFC1918 and cloud-metadata addresses are refused.

**The general lesson.** "Let the model retrieve it" trades a quota you can see for
an input you cannot inspect. Determinism in what the model sees is worth real
engineering effort, because without it you cannot tell a genuine improvement from
the model having happened to read something different that day.

### 6.4 Parallel harnesses → the connector owns its counters

**What I built.** Evaluation tooling that reproduced the connector's decision logic
so batches could be scored offline.

**What went wrong.** The harness and the connector drifted. Once they disagree you
are measuring the harness, and the more convincing the harness's numbers, the
worse the problem — you cannot tell a real improvement from a divergence.

**The reversal.** The connector emits its own per-category outcome matrix
(`metrics.py`), appended as JSON lines to `ai_metrics.jsonl` beside the audit log.
Anything the logs say about behaviour comes from the code path that made the
decision. The remaining offline tools (`tools/label.py`, `tools/score.py`) score
and label *recorded outcomes*; they do not re-implement any decision.

**The general lesson.** An evaluation harness that duplicates production logic is a
second implementation you now have to keep correct, and it fails silently. Prefer
instrumenting the real path.

### 6.5 Name-shape heuristics → report-class context

**What I built.** Victim-versus-actor discrimination from the shape of the name:
legal-form suffixes, company markers, and so on.

**What went wrong.** Ransomware reporting breaks it in both directions. Gangs
adopt corporate-looking brands. Victims are referred to without their legal suffix.
And in ransomware coverage specifically, a malware name and an actor name for the
same brand is *correct*, not a contradiction — the rule that suppresses
double-filing elsewhere is wrong here.

**The reversal.** The connector classifies the source material first
(`_ransomware_context`) and applies different rules downstream. `has_victim_context`
and `is_leak_site_operator` take the surrounding text as evidence rather than
judging the name in isolation, and `_name_regex_forms` finds that evidence across
spelling variants. The entity's own title is legitimate evidence too — it has the
same provenance as the content, so an acronym the title spells out is a
canonicalisation the connector is entitled to make.

**The general lesson.** A name carries less information than people building
extractors assume. Where the meaning depends on the kind of document, classify the
document.

### 6.6 Unsupervised critic → a vetted, subordinate critic

**What I built.** A second model pass to review the first pass's output and clean
it up.

**What went wrong.** It agreed with the first pass. Same family, same
distribution, same blind spots — and now with two votes, which reads as
corroboration and is not.

**The reversal.** The critic is confined to `DROP` and `RECLASSIFY` and runs
*before* the deterministic layer, so its verdicts are themselves subject to the
guards. It is off by default. It is genuinely useful for the errors a pattern
cannot express — "this is the victim, not the actor" in a sentence with no
suffix-based tell — and useless as an approver.

**The general lesson.** Two correlated estimators are one estimator with worse
error bars. A second model call is worth adding when it can only subtract.

### The pattern

Six reversals, one direction: every time reality disagreed with the design, the
answer was less model authority and more deterministic refusal. The guards did not
get smarter — several categories got their creation capability *removed*. If
there is a transferable claim in this project, it is that one.

---

## 7. The self-feedback loop

The reversals above were a human reading evidence. The parts of that cycle that
can be mechanised, are.

**The ledger.** In `dry-run`, every would-create is logged with its name,
category, confidence, which gates it passed, and what it would have linked to.
This is the raw material. `AI_AUDIT_LOG` makes it survive container recreation,
which matters because container logs die with the container and an evaluation that
runs for weeks would otherwise lose its own evidence to a redeploy.

**The counters.** `metrics.py` maintains a per-category outcome matrix — linked,
would-create, refused and by which guard, and `link_rate`. Per-category is the
load-bearing detail: an aggregate precision number is useless for deciding
anything, because the categories fail differently and at different rates. Summaries
append to `ai_metrics.jsonl`, so behaviour over time is a file you can analyse
rather than a memory you have to trust.

**The promotion gate.** `AI_CREATE_*` per category is the unit of change. A
category moves `off` → `dry-run` → `on` on its own evidence, independently of the
others. Categories that never earn it never get promoted, and two of them had their
capability deleted instead.

Per-category is the load-bearing detail, because the categories behave nothing like
each other. Techniques and countries resolve cleanly and consistently — those are
the easy wins. Victims are the opposite: a large share of the organisations the
model names are not in the knowledge base at all, and promoting that category on
faith would mean inventing companies. On a blended average, victims hide behind
techniques and the overall picture looks fine. That is the counterfactual that
matters: with one global create flag, CVE creation would have shipped alongside the
categories that genuinely worked, because the aggregate looked acceptable.
[OBSERVATIONS.md](OBSERVATIONS.md#where-it-goes-wrong) has the specifics.

**The mechanised part.** `AI_ALIAS_WRITEBACK` is the genuinely self-improving
path. Aliases the model discovers are written back onto the entity, so the next
run's dedup is better than this run's — a name that fragmented into two entities
last month matches correctly next month. It is off by default, because unlike
everything else it modifies a pre-existing entity nobody asked the connector to
touch. `AI_CONFIDENCE_CALIBRATION_OFFSET` and age-based confidence decay are the
blunter instruments in the same family.

**The part that is not automated, and should not be.** Nothing promotes itself. No
threshold auto-tunes. A system that widens its own write permissions based on its
own scoring has no external check at all, and the failure is silent and
compounding. The loop closes on a human reading the ledger — the work the loop
removes is *finding* the problem, not deciding what to do about it. The CVE
reversal is the example: the loop surfaced the bad identifiers within a normal
review; no amount of automated tuning would have concluded "delete this
capability," because that conclusion required knowing what NVD is for.

---

## 8. The one-person threat team

This is the claim I find most interesting and want to state carefully, because the
overclaimed version of it is everywhere.

**What does not work: a person plus a chatbot.** Paste the report, ask for the
actors, paste the answer into the platform. It is faster than reading and it is
unauditable, unreproducible, and wrong at an unknown rate. You have added
throughput and removed the ability to know if you are right. Over a few years of
watching people use models this way, the pattern is consistent: the output quality
tracks the operator's ability to check it, and checking is the expensive part.

**What does work: a person plus an engineered funnel.** The difference is where the
judgement lives. In the chatbot version, judgement is applied per item by a human
who is now a bottleneck and getting bored. In the funnel version, judgement is
applied *once*, to the rules, and then executed identically on every item forever.
`is_security_product` encodes "the defender's EDR is not the adversary's tool" one
time. It then holds on every report, at 3am, on the ten-thousandth item, without
attention.

That is the actual leverage, and it is a specific, bounded claim:

- **What scales: consistent application of settled judgement.** Deterministic code
  does not get tired, does not have a bad week, and does not apply the rule
  differently in December than in March. This is most of the volume.
- **What does not scale, and is now where the person spends their time:** deciding
  what the rules should be, reading the would-create ledger, and knowing that NVD
  owns CVE identifiers. This is the part worth a salary.

**The honest accounting.** Building it this way is slower than pointing a model at
a feed and turning it on. The observation period before a category is allowed to
write costs real time, and it is a genuinely awkward position to hold in a team
with a roadmap — someone will reasonably ask why the AI connector is being careful
instead of producing.

The CVE reversal is the answer, and it is worth being concrete about it. During that
period the pipeline was confidently proposing vulnerability identifiers that do not
exist anywhere, including some it could justify from the source text. Had creation
been on from day one, those would be in the graph now, indistinguishable from real
CVEs, cited by whatever queried them. Instead the capability is gone and the graph
is clean. The value of an observation period is entirely counterfactual, which is
exactly why it is so easy to skip and so expensive to have skipped.

**Where the industry argument in §3 lands.** If security expertise is converging
with inference, the differentiated work is not prompting. It is knowing which
decisions a model is allowed to make. That knowledge is what this repository is:
a few thousand lines of guards and vocabularies and dedup, a comparable volume of
tests pinning them in place, and a fifteen-line module that actually talks to the
model.

---

## 9. What this does not do

- **It is not a general AI-for-CTI platform.** It is one OpenCTI enrichment
  connector against one model provider, scoped to six entity types.
- **Only Gemini has been run.** `llm.py` isolates the vendor SDK to one small
  module, which would make another provider a contained change, but I have not
  done it and the repo does not pretend otherwise. There is no provider
  abstraction, because an interface with one implementation advertises portability
  it has not demonstrated.
- **It is not autonomous.** Which categories may write is a human decision, made
  per category, informed by what the logs show.
- **It is not a fix for attribution gaps.** Where the source material does not
  attribute, the model generally does not either — there is a worked example of
  that in [OBSERVATIONS.md](OBSERVATIONS.md#it-declines-exactly-where-the-feed-declines).
- **The evaluation corpus is not shippable.** The labelled victim corpus behind the
  guard work is real breach reporting about real organisations. `tools/label.py` and
  `tools/score.py` are published as the methodology; the data is not, and there is
  no synthetic substitute in this repo — a fabricated corpus produces something
  that looks like evidence and is not.
- **This is experience from one deployment, one feed, one stretch of time.** The
  patterns in [OBSERVATIONS.md](OBSERVATIONS.md) are what I saw, described as
  honestly as I can. They are not a benchmark and should not be read as one; your
  sources and your knowledge base will differ.
- **Guards are code and code is wrong.** The mitigations are reversibility via
  `AI_REVIEW_LABEL`, cautious defaults, and 374 tests concentrated on the guard
  layer — not an assumption that the guard layer is correct.
