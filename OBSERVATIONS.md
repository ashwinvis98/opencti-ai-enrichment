# What Gemini got right, and what it got wrong

Field notes from running this against a live OSINT feed for a while. Not a
benchmark — there is no held-out labelled set for "did the connector correctly
decline to invent an organisation", and I am not going to fabricate one and call
the output a score.

Read this as experience, because that is what it is. The useful content is the
*shape* of the failures, not a number attached to them. If you are building
something similar, the failures are the part that will cost you time.

The short version: **Gemini is genuinely good at this, and it is also capable of
quietly poisoning a knowledge graph.** Both of those are true at the same time,
and which one you get depends almost entirely on what you let it write.

---

## Where it works, and works well

**Reading prose and naming what is in it.** This is the thing modern models are
actually good at, and it is most of the job. Given a vendor write-up, Gemini
reliably comes back with the actor, the malware family, the techniques, the
targeted sectors and the countries — as structured fields, conforming to the
schema it was asked for. That is not a small thing. It is the operation the whole
pipeline is built around.

**ATT&CK technique identification is the standout.** I expected this to be the
weak spot, because a model inventing `T1XXX` identifiers would be both easy to do
and hard to notice. It essentially does not happen. Techniques it names
overwhelmingly resolve to real, already-imported ATT&CK entities. I built the
lookup-only restriction expecting it to throw away a meaningful amount of good
output, and it throws away almost nothing. The guard that felt most severe when I
wrote it turned out to be the cheapest one in the system.

**Thin reports are where it changes the answer.** A lot of feed content arrives
nearly bare — a title, a short description, a handful of indicators, and one or
two links to anything meaningful. Two real examples:

- *The Closed Quorum: Inside the first reported autonomous AI C2 implant*
  ([Cisco Talos](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/))
  arrived with essentially one graph-building object attached to it.
- *Placeholder Domains Whose Ads Serve Scams*
  ([Manifold Security](https://www.manifold.security/blog/placeholder-domains-ads-serve-scams))
  arrived in the same state.

On reports like those, the connector goes from "a node with some indicators
hanging off it" to something that answers a query. That is the case for doing this
at all, and it is much stronger on thin content than on rich content.

**It fills the gap the feed structurally leaves.** *DarkMe RAT: A VB6 APT Trojan
Turned Conventional Infostealer* — the feed's title for
[a Huntress write-up](https://www.huntress.com/blog/darkme-rat-abandons-exploits)
headlined differently — is the example I keep coming back to. A report named after
a malware family, carrying hundreds of indicators, and barely connected to that
family. The feed had done the mechanical part perfectly and skipped the judgement.
Gemini named the family and the actor from the prose, which is exactly the work
that was missing.

*Konni Hackers Target Ukraine With Malicious LNK Files and VelvetCake PowerShell
Malware* ([Cyber Press](https://cyberpress.org/konni-targets-ukraine-with-velvetcake/))
behaved similarly — it came in with a small handful of graph links and the model
named the actor, two malware families, a set of techniques, several sectors and a
country. The report was already *about* all of that. Nothing was inferred; it was
read.

> A note on the titles in this document: they are the report names **as the feed
> recorded them**, which is not always the vendor's own headline. Feeds retitle. It
> is a small thing, but it is the title in the graph that an analyst searches
> against, so it is the one worth quoting.

**Deterministic wins.** Countries resolve essentially perfectly. CVEs that already
exist resolve essentially perfectly. Where the title spells out an acronym the
body uses, canonicalisation picks it up. These are boring and they matter, because
they are the categories where you can stop worrying.

---

## Where it goes wrong

### Inventing CVE identifiers — the one that changed my mind

This is the failure I would lead with if I were warning someone.

Gemini proposes CVE identifiers that do not exist. Not malformed — perfectly
well-formed, plausible, correctly-shaped identifiers that are present at neither
NVD nor CVE.org. And the part that actually matters: **some of them arrive
verbatim in the source feed's own report title.** Which means the identifier *is*
in the document, which means a groundedness check — "is this name traceable to the
source text?" — passes it and waves it through.

The guard I had built to catch exactly this class of error was structurally
incapable of seeing it. That is much worse than a weak guard, because a weak guard
makes you cautious and a blind guard makes you confident. Creating those entities
would have been permanent graph debt in the service of somebody else's typo.

CVE creation is now gone. Not disabled — removed, with no configuration switch and
a test asserting it stays removed. NVD owns vulnerability identifiers; the correct
operations are *look up* and *fail*.

### Filing the victim as the attacker

The single most damaging thing this pipeline can do, and the most natural mistake
for a model to make.

Ransomware and extortion reporting names the breached organisation far more often,
and far more prominently, than it names the gang. Count the mentions and the victim
wins. A naive extractor takes the most prominent organisation and files it as the
threat actor, and now your graph asserts that a hospital attacked somebody. It
looks structurally identical to a true relationship, it carries a confidence
score, and it will get cited.

Getting this right needed more than name shapes. Gangs adopt corporate-looking
brands; victims get referred to without their legal suffix. The connector has to
classify the *document* first — is this ransomware reporting? — and then read the
surrounding sentences as evidence about each name, across the spelling variants the
name appears in. Judging the name in isolation does not work.

### Naming organisations that do not exist

A large share of the victim organisations Gemini names are not in the knowledge
base. Some are real companies that simply have not been recorded yet. Some are
artefacts — a department, a product, a partially-read company name. Creating them
all would mean inventing organisations, and victims are far and away the noisiest
category in this respect. Nothing else comes close.

This is the clearest argument for gating entity creation *per category* rather than
globally. On a blended average, victims hide behind techniques and the overall
number looks fine.

### Quietly fragmenting a curated taxonomy

Sectors are a maintained, alias-rich vocabulary — a few dozen canonical entries
doing real work. Gemini regularly proposes sector names that match none of them:
reasonable-sounding, slightly-off variants.

Turn on free-text sector creation and a feed will grow those few dozen canonical
sectors into several hundred near-duplicates in short order. The damage is
invisible and permanent: nothing errors, no dashboard drops, and from then on every
sector-scoped query silently returns a less complete answer than it should. This is
my favourite example of an AI failure that does not look like a failure.

### Confusing the software in the report with the software of the attack

A report about exploiting Microsoft Exchange mentions Exchange constantly. The
model's type assignment is much weaker than its extraction, so Exchange gets filed
as the malware. Same pattern with the defender's own tooling — a report describing
how an EDR detected something can end up recording that EDR as a tool used by the
adversary. Both invert the meaning of the report.

These are handled by explicit vocabularies, and honestly that is the least elegant
part of the codebase. There is no clever general rule. Somebody has to write down
that Exchange is infrastructure and CrowdStrike is a security product, once, and
then it holds forever.

### Confidence that means nothing

Gemini reports high confidence on nearly everything. Not "high on the easy ones" —
high on almost every document regardless of how thin, ambiguous or contradictory
the source was.

A confidence signal that does not vary carries no information. The connector
currently writes that self-reported confidence into the entity's score, which means
the score is provenance, not quality. This is the weakest part of the design as it
stands, and treating those numbers as a filter would be a mistake.

### It declines exactly where the feed declines

*Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix*
([Huntress](https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat)) is the
example that keeps me honest. Interesting report, well populated with indicators,
no actor attribution from the feed. Gemini named **no actor and no malware
family** — only techniques.

So enrichment is not a general fix for attribution gaps. On the report where the
missing attribution was the most interesting thing about it, the model was as
silent as the feed. Worth knowing before you promise anyone that AI will connect
your graph.

### Two models agreeing is not verification

An early version had a second Gemini pass review the first pass's output and clean
it up. It agreed with it. Same family, same training distribution, same blind
spots — and now with two votes, which reads like corroboration and is not.

The critic is still there, but it can only *subtract*: drop or reclassify, never
approve. It runs before the deterministic layer, so its verdicts are themselves
subject to the guards. In that shape it earns its keep on errors a pattern cannot
express — "this is the victim, not the actor", in a sentence with no suffix-based
tell. As an approver it was worse than nothing.

### Hollow entities, from the very first version

The earliest proof of concept created Attack-Pattern entities from whatever
technique names came back. The result was entities in the ATT&CK namespace that
ATT&CK has never heard of, with no description and no relationships. They are worse
than absent, because every later query that assumes the namespace means something
now returns them.

That behaviour was inherited into the real connector and carried forward as an
explicit requirement before anyone questioned it. Worth flagging as a process
failure rather than a model failure: the model did what it was asked. Nobody asked
whether it should have been.

---

## So why is "just enrich it with Gemini" the wrong instinct?

Because the good and the bad arrive in the same shape.

A hallucinated indicator is noise, and noise is survivable — it sits in a list,
nobody builds on it, and it ages out. A hallucinated **relationship** is a false
claim about the world. It has a confidence score. It is structurally
indistinguishable from the true relationships next to it. It will be picked up by a
query, put in front of somebody, and acted on. Nothing about its appearance tells
you it was invented.

And the errors are not random, they are *systematic*. The model does not
occasionally slip on victim-versus-actor — it gets it wrong in a consistent
direction, on a whole genre of reporting, every time. That is much worse than
random error for a knowledge graph, because it means the wrongness accumulates in a
pattern that looks like a finding.

The other half of it: nothing pages you. A graph with fabricated CVEs and
hundreds of duplicate sectors and a hospital filed as a threat actor throws no
errors, fails no health check, and shows more objects than it did last month. The
first symptom is a decision made on a bad answer, and by then you cannot tell which
answers were bad.

So the model gets to propose, and deterministic code decides. Not because the model
is bad at this — it is good at it — but because "good at it" and "trusted to write
to a shared knowledge base" are very different bars.

---

## How to tell which one you are getting

The connector logs every decision it makes, including the ones it refuses and the
entities it *would* have created if it were allowed to. That is the point of
`dry-run` existing as a value between off and on: a boolean forces a choice between
having no evidence and having live writes, and dry-run gives you the full ledger at
no risk.

A rollout that works:

1. Start read-only with creation in `dry-run`, and a read-only OpenCTI token so the
   guarantee is structural rather than conditional on my code being correct.
2. Read the would-create ledger. Not for a day — long enough for the noisy
   categories to show you what they are.
3. Promote **one category at a time**, and only the ones whose behaviour you have
   actually looked at. Per-category gating exists because precision is not uniform
   and the aggregate hides the problem.
4. Some categories should never be promoted. Two of them here had their capability
   deleted rather than tuned.

The CVE reversal is the argument for step 2 in a sentence: those identifiers were
proposed during the observation period, they do not exist, and they are not in
anybody's graph — because nothing was being written yet while I was still learning
what the model got wrong.

---

## What is reproducible without any of this

You do not have to take any of the above on faith to evaluate the code. Clone it
and run the suite — no credentials, no network, no OpenCTI:

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q          # 374 passed
```

That is what CI runs, so the "works without credentials" claim is enforced rather
than asserted. Most of those tests encode a specific thing that went wrong once:
the vocabularies, the victim-versus-actor discrimination, the identifier
validation, the SSRF refusals on reference fetching. A couple of them exist purely
to assert that CVE creation has not come back.

The whole model-calling surface is `enrichment/llm.py`, which is 15 lines. Almost
none of this project is about calling a model.
