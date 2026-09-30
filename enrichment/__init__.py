"""opencti-guarded-enrichment.

An OpenCTI INTERNAL_ENRICHMENT connector where the language model PROPOSES
entities and relationships and deterministic code DECIDES what, if anything,
reaches the knowledge graph.

Module map, in dependency order:

    prompts     typed extraction contracts, one per entity type, plus the critic
    names       normalisation and the three dedup key layers
    orgs        organisation keys, acronyms, title-derived canonicalisation
    grounding   deterministic source-evidence check (gates creation only)
    guards      the vocabularies and predicates that refuse bad entities
    relations   relationship type/direction against OpenCTI's own schema
    fetch       reference retrieval with SSRF protection
    vocab       STIX open-vocabulary normalisers
    metrics     per-category outcome matrix and link_rate
    llm         the Gemini call - the only vendor SDK import
    connector   configuration, pipeline, and the decision funnel

Start with guards.py. That is where the interesting failures live.
"""
