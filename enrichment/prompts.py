"""Prompt templates.

One per supported entity type, plus the critic prompt. Every entity prompt
appends _CLASSIFY_RULES, which is where the type/role discipline lives:
asking for TYPED extraction rather than flat name lists is what stopped the
model dumping victims, tools and malware into one undifferentiated bucket."""

# ---------------------------------------------------------------------------
# System preamble shared by all prompt templates
# ---------------------------------------------------------------------------

SYSTEM_PREAMBLE = (
    "Act as an experienced threat intelligence analyst preparing source "
    "material for a structured knowledge graph. "
    "Your entire reply must be one JSON object and nothing besides it: no "
    "commentary, no preamble, no explanation, and no code fences of any kind. "
    "Base your analysis on your own knowledge and, where available, live web "
    "research — NOT on any pre-existing database classification. "
    "If external reference URLs are provided, treat them as primary sources and "
    "investigate them. "
    "If the input content is in a language other than English, analyze it in its "
    "original language but ALWAYS return the JSON response with all string values "
    "in English.\n\n"
)

# ---------------------------------------------------------------------------
# Prompt templates — each returns a strict JSON object.
# `suggested_labels` is common to all: short lowercase tags for OpenCTI.
# ---------------------------------------------------------------------------

# Shared classification rules injected into every prompt. This is where the
# type/role discipline lives — it turns flat name-dumping into typed extraction.
_CLASSIFY_RULES = """
CLASSIFICATION RULES (critical):
- "software" is ONLY malware or tools USED BY THE ATTACKER to conduct the
  intrusion. Each item MUST be classified: set "kind" to "malware" for malicious
  code (ransomware, trojans, backdoors, wipers, stealers, RATs); set "kind" to
  "tool" for LEGITIMATE or dual-use software the ATTACKER abused — remote-access/
  RMM (AnyDesk, TeamViewer, PsExec), scanners (nmap, nuclei), sysadmin/backup/VPN
  utilities. Set "legitimate" true for benign/dual-use software, false for malware.
- Do NOT put the VICTIM's own software, the breached/affected product, or software
  merely mentioned as impacted into "software" — those belong in "affected_products".
  (e.g. if attackers breached a company running PTC Windchill or Pandora FMS, those
  are affected_products, NOT attacker tools.)
- "threat_actors" are ATTACKERS only. NEVER put victim organisations, targeted
  companies, security vendors, or product names in "threat_actors".
- "victims" are organisations that were TARGETED/breached (the victim of the attack).
- Only include SPECIFIC, NAMED entities. Exclude generic descriptors
  ("state-sponsored actors", "unknown group"), single generic words, commands,
  file names, and numeric/symbol tokens.
- Use empty lists when nothing applies. Return raw JSON only.
"""

REPORT_PROMPT = SYSTEM_PREAMBLE + """Analyze this threat intelligence report.
Return JSON with exactly these keys:
- summary: string (3-4 sentence executive brief, plain text)
- threat_actors: list of strings (ATTACKER group/actor names only)
- victims: list of strings (organisations TARGETED or breached in this report)
- software: list of objects, each {"name": string, "kind": "malware"|"tool", "type": string (e.g. "ransomware","remote-access","backdoor"), "legitimate": boolean} (ATTACKER tools/malware ONLY)
- affected_products: list of strings (the victim's / breached / impacted software products; NOT attacker tools)
- attack_techniques: list of strings (MITRE ATT&CK IDs only, e.g. ["T1059.001", "T1003"])
- cves: list of strings (CVE IDs explicitly referenced, e.g. ["CVE-2023-34362"])
- targeted_sectors: list of strings (e.g. ["Finance", "Healthcare", "Government"])
- targeted_countries: list of strings (ISO 3166-1 alpha-2, e.g. ["US", "UA", "DE"])
- suggested_labels: list of strings (short lowercase tags, e.g. ["ransomware", "phishing"])
- confidence: integer 0-100
""" + _CLASSIFY_RULES + """
Report:
{content}"""

INTRUSION_SET_PROMPT = SYSTEM_PREAMBLE + """Analyze this threat actor / intrusion set profile.
Return JSON with exactly these keys:
- summary: string (3-4 sentence executive brief)
- aliases: list of strings (other known names for THIS actor)
- software: list of objects, each {"name": string, "kind": "malware"|"tool", "type": string, "legitimate": boolean} (malware/tools this actor uses)
- attack_techniques: list of strings (MITRE ATT&CK IDs)
- cves: list of strings (CVE IDs this actor is known to exploit)
- targeted_sectors: list of strings (sectors this actor targets)
- targeted_countries: list of strings (ISO 3166-1 alpha-2 codes)
- motivation: string (one of: "espionage","financial","hacktivism","destruction","ideology","notoriety","revenge","unknown")
- resource_level: string (one of: "individual","club","contest","team","organization","government","unknown")
- goals: list of strings (stated objectives)
""" + _CLASSIFY_RULES + """
Profile:
{content}"""

THREAT_ACTOR_PROMPT = SYSTEM_PREAMBLE + """Analyze this threat actor profile.
Return JSON with exactly these keys:
- summary: string (3-4 sentence executive brief)
- aliases: list of strings (other known names for THIS actor)
- motivation: string (one of: "espionage","financial","hacktivism","destruction","ideology","notoriety","revenge","unknown")
- sophistication: string (one of: "none","minimal","intermediate","advanced","expert","innovator","strategic","unknown")
- resource_level: string (one of: "individual","club","contest","team","organization","government","unknown")
- roles: list of strings (e.g. "agent","director","malware-author")
- goals: list of strings (stated objectives)
- software: list of objects, each {"name": string, "kind": "malware"|"tool", "type": string, "legitimate": boolean}
- attack_techniques: list of strings (MITRE ATT&CK IDs)
- cves: list of strings (CVE IDs this actor is known to exploit)
- targeted_sectors: list of strings
- targeted_countries: list of strings (ISO 3166-1 alpha-2)
- suggested_labels: list of strings (short lowercase tags)
- confidence: integer 0-100
""" + _CLASSIFY_RULES + """
Profile:
{content}"""

MALWARE_PROMPT = SYSTEM_PREAMBLE + """Analyze this malware profile.
Return JSON with exactly these keys:
- summary: string (3-4 sentence executive brief)
- is_family: boolean (true if this is a malware family rather than a single sample)
- malware_type: string (one of: "ransomware","trojan","backdoor","worm","virus","rootkit","spyware","keylogger","downloader","dropper","wiper","webshell","bot","remote-access-trojan")
- capabilities: list of strings (key capabilities)
- implementation_languages: list of strings (e.g. ["c","python","go"])
- attack_techniques: list of strings (MITRE ATT&CK IDs)
- cves: list of strings (CVE IDs this malware exploits)
- targeted_sectors: list of strings
- associated_threat_actors: list of strings (ATTACKER names that use this malware)
- suggested_labels: list of strings (short lowercase tags)
- confidence: integer 0-100
""" + _CLASSIFY_RULES + """
Profile:
{content}"""

CAMPAIGN_PROMPT = SYSTEM_PREAMBLE + """Analyze this threat campaign.
Return JSON with exactly these keys:
- summary: string (3-4 sentence executive brief)
- first_seen: string (ISO 8601 date or empty string if unknown)
- last_seen: string (ISO 8601 date or empty string if unknown)
- objective: string (the campaign's goal, or empty string)
- attack_techniques: list of strings (MITRE ATT&CK IDs)
- software: list of objects, each {"name": string, "kind": "malware"|"tool", "type": string, "legitimate": boolean} (ATTACKER tools/malware ONLY)
- affected_products: list of strings (victim's / impacted software products; NOT attacker tools)
- threat_actors: list of strings (ATTACKER names)
- cves: list of strings (CVE IDs exploited in this campaign)
- targeted_sectors: list of strings
- targeted_countries: list of strings (ISO 3166-1 alpha-2)
- suggested_labels: list of strings (short lowercase tags)
- confidence: integer 0-100
""" + _CLASSIFY_RULES + """
Campaign:
{content}"""

VULNERABILITY_PROMPT = SYSTEM_PREAMBLE + """Analyze this vulnerability.
Return JSON with exactly these keys:
- summary: string (3-4 sentence executive brief)
- cvss_score: string (CVSS base score as string, or empty string if unknown)
- cvss_severity: string (one of: "low","medium","high","critical", or empty string)
- cisa_kev: boolean (true if listed in CISA Known Exploited Vulnerabilities)
- epss: string (EPSS probability 0-1 as string, or empty string if unknown)
- attack_techniques: list of strings (MITRE ATT&CK IDs relevant to exploitation)
- affected_software: list of strings (affected product names)
- associated_threat_actors: list of strings (ATTACKER names known to exploit this CVE)
- suggested_labels: list of strings (short lowercase tags)
- confidence: integer 0-100
""" + _CLASSIFY_RULES + """
Vulnerability:
{content}"""

# Critic / verification prompt — a cheap second-pass quality reviewer. Runs on
# the LOW model with no search; catches mis-typed / junk / victim-as-actor items
# that the deterministic guards cannot.
CRITIC_PROMPT = SYSTEM_PREAMBLE + """You are a CTI data-quality reviewer. Another analyst
extracted the entities below from a source, each with a proposed classification.
Identify ONLY the mistakes. Return JSON with exactly these keys:
- drop: list of strings — names that are NOT real named threat entities (generic
  descriptors, single generic words, commands, file names, numeric/symbol tokens,
  product marketing terms, or nonsense).
- actor_to_victim: list of strings — names listed as threat actors that are actually
  victim/targeted organisations or security vendors, not attackers.
- to_tool: list of strings — names listed as malware that are actually legitimate or
  dual-use software (RMM/remote-access, scanners, admin/backup utilities, AI/LLM products).
- to_malware: list of strings — names listed as tools that are actually malicious code.
Use empty lists where nothing applies. Output raw JSON only.

Candidates:
{content}"""

