"""The deterministic guard layer.

Roughly a quarter of the connector, and every predicate here exists because
of something the connector actually got wrong in production. None of it
involves a model call.

The single most important property: these gate CREATION, not LINKING. They
are applied after resolution, so a name that already exists in the graph
still links. Minting a new entity is durable graph debt; linking to an
existing one is cheap and reversible."""
import re
from .names import _norm_name, _dedup_key, _LEET_MAP, _SUFFIX_TOKENS
from .grounding import _grounding_haystack, _STOPWORD_TOKENS
from .orgs import _ORG_SUFFIX, _ORG_STOP, _LEGAL_FORM_SUFFIX

_SUFFIX_TOKENS = ("group", "team", "gang", "crew", "the")

# Exact normalised names that are always generic (never create/link).
_GENERIC_EXACT = frozenset({
    "unknown", "n/a", "na", "none", "various", "multiple", "other", "others",
    "tbd", "unidentified", "unattributed", "adversary", "adversaries",
    "attacker", "attackers", "threat actor", "threat actors", "actor", "actors",
    "hackers", "cybercriminals", "cyber criminals", "criminals",
})

# Substrings that mark a name as a generic descriptor rather than a proper name.
# NOTE: deliberately does NOT include bare "group"/"team"/"actor" — real names
# contain those (Equation Group, Lazarus Group). Only descriptor phrases.
_GENERIC_MARKERS = (
    "state-sponsored", "state sponsored", "nation-state", "nation state",
    "based threat actor", "based threat actors", "based actors", "based group",
    "cybercriminal", "cyber criminal", "financially motivated",
    "ransomware operators", "ransomware affiliates", "affiliates",
    "unidentified", "unattributed", "unknown ", "several ", "various ",
    "multiple ", "threat actors", "threat-actors",
    # Descriptive phrases Gemini emits instead of a malware/tool NAME. These are
    # capability descriptions, not named families, and each one would become a
    # single-use orphan entity (observed: "custom Python exploit scripts",
    # "Reverse SSH Tunneling Tool", "Gmail-stealing Chrome extension", "AI C2").
    "custom ", "bespoke ", "in-house ", "homemade ", "unnamed ",
    "exploit script", "exploit kit script", "reverse shell", "reverse ssh",
    "reverse-tunnel", "reverse tunnel", "web shell", "webshell",
    "browser extension", "chrome extension", "firefox extension",
    "-stealing", " stealer script", "powershell script", "python script",
    "batch script", "shell script", "vbs script", "macro document",
    "phishing kit", "phishing page", "phishing email", "phishing site",
)

# ---------------------------------------------------------------------------
# Collective descriptors — "Chinese banks", "European financial institutions",
# "government agencies". These name a CLASS of organisations, not an
# organisation, so creating one mints an entity that can never be correct. They
# slipped through because _GENERIC_MARKERS only matches fixed phrases.
#
# The test is compositional: a name is a collective descriptor when it contains
# at least one PLURAL organisation word AND every one of its tokens is drawn
# from these closed vocabularies. Requiring the plural is what keeps real names
# safe — "Cobalt Bank & Trust Company" has 'bank' but also 'cobalt' and 'trust',
# and "Bank of Kalinda" survives because 'kalinda' is a place NOUN, not one of
# the nationality ADJECTIVES below.
# ---------------------------------------------------------------------------

# Nationality/region ADJECTIVES only. Deliberately excludes the noun forms
# ("china", "russia", "japan") so real names containing a place survive.
_NATIONALITY_ADJ = frozenset({
    "chinese", "russian", "american", "european", "asian", "african", "indian",
    "japanese", "korean", "german", "french", "british", "english", "israeli",
    "iranian", "iraqi", "ukrainian", "brazilian", "mexican", "canadian",
    "australian", "spanish", "italian", "dutch", "turkish", "saudi", "emirati",
    "egyptian", "nigerian", "vietnamese", "thai", "indonesian", "malaysian",
    "singaporean", "taiwanese", "polish", "swedish", "norwegian", "danish",
    "finnish", "swiss", "austrian", "belgian", "greek", "portuguese", "czech",
    "hungarian", "romanian", "pakistani", "bangladeshi", "filipino", "syrian",
    "lebanese", "jordanian", "qatari", "kuwaiti", "moroccan", "algerian",
    "tunisian", "kenyan", "ethiopian", "argentine", "argentinian", "chilean",
    "colombian", "peruvian", "venezuelan", "cuban", "us", "uk", "eu", "usa",
    "western", "eastern", "northern", "southern", "middle", "east", "west",
    "north", "south", "central", "latin", "nordic", "baltic", "balkan",
    "domestic", "foreign", "regional", "national", "multinational", "overseas",
})

# PLURAL organisation/collective nouns. Presence of one of these is required
# before a name can be judged a collective descriptor.
_ORG_PLURAL_WORDS = frozenset({
    "banks", "companies", "corporations", "corporates", "organizations",
    "organisations", "agencies", "hospitals", "clinics", "universities",
    "colleges", "schools", "governments", "ministries", "institutions",
    "institutes", "firms", "enterprises", "providers", "retailers",
    "manufacturers", "operators", "carriers", "airlines", "utilities",
    "telecoms", "telcos", "insurers", "entities", "businesses", "offices",
    "departments", "municipalities", "contractors", "suppliers", "vendors",
    "customers", "clients", "hotels", "restaurants", "casinos", "pharmacies",
    "laboratories", "labs", "factories", "plants", "refineries", "ports",
    "airports", "railways", "hospitalities", "cooperatives", "unions",
    "associations", "foundations", "charities", "nonprofits", "ngos",
    "startups", "conglomerates", "subsidiaries", "branches", "chains",
    "outlets", "stores", "shops", "operators", "authorities", "councils",
    "bodies", "regulators", "brokerages", "exchanges", "lenders", "creditors",
    "publishers", "broadcasters", "outfits", "groups", "teams", "sectors",
    "industries", "networks", "systems", "sites", "websites", "servers",
    "individuals", "citizens", "residents", "patients", "students",
    "employees", "officials", "executives", "journalists", "activists",
    "researchers", "users", "victims", "targets", "organisations",
})

# Singular organisation / sector / structural words. These may appear but are
# never enough on their own — they only fail to save a name.
_ORG_GENERIC_WORDS = frozenset({
    "bank", "company", "corporation", "organization", "organisation", "agency",
    "hospital", "clinic", "university", "college", "school", "government",
    "ministry", "institution", "institute", "firm", "enterprise", "provider",
    "retailer", "manufacturer", "operator", "carrier", "airline", "utility",
    "telecom", "insurer", "entity", "business", "office", "department",
    "municipality", "contractor", "supplier", "vendor", "customer", "client",
    "sector", "industry", "network", "system", "site", "website", "server",
    "authority", "council", "body", "regulator", "exchange", "lender",
    "publisher", "broadcaster", "association", "foundation", "charity",
    "cooperative", "union", "group", "team", "chain", "outlet", "store",
    # sector qualifiers
    "financial", "finance", "healthcare", "health", "medical", "energy",
    "banking", "telecommunications", "education", "educational",
    "manufacturing", "retail", "insurance", "transportation", "transport",
    "logistics", "defense", "defence", "technology", "tech", "pharmaceutical",
    "pharma", "automotive", "aerospace", "chemical", "mining", "agriculture",
    "agricultural", "construction", "hospitality", "legal", "media",
    "critical", "infrastructure", "public", "private", "commercial",
    "industrial", "municipal", "federal", "state", "provincial", "local",
    "small", "medium", "large", "major", "leading", "prominent", "key",
})

# Quantifiers/determiners that carry no identity.
_QUANTIFIER_WORDS = frozenset({
    "several", "multiple", "various", "many", "some", "numerous", "dozens",
    "hundreds", "thousands", "a", "an", "the", "of", "and", "or", "in", "at",
    "on", "for", "to", "other", "others", "certain", "additional", "further",
    "least", "over", "least",
})

_COLLECTIVE_OK = (_NATIONALITY_ADJ | _ORG_PLURAL_WORDS | _ORG_GENERIC_WORDS
                  | _QUANTIFIER_WORDS)


def is_collective_descriptor(value) -> bool:
    """True if the name describes a CLASS of organisations, not one organisation.

    "Chinese banks", "European financial institutions", "government agencies",
    "multiple US hospitals" -> True. Real names survive because they contain at
    least one token outside the closed vocabularies: "Cobalt Bank & Trust
    Company", "Bank of Kalinda", "Larkfield Research Group", "Astora State Navy".
    """
    n = _norm_name(value)
    if not n:
        return False
    tokens = [t for t in re.split(r"[^a-z0-9]+", n) if t]
    if not tokens:
        return False
    if not any(t in _ORG_PLURAL_WORDS for t in tokens):
        return False
    return all(t in _COLLECTIVE_OK for t in tokens)


def is_generic_entity_name(value) -> bool:
    """True if the name is a generic descriptor that must never be created/linked."""
    n = _norm_name(value)
    if not n:
        return True
    if n in _GENERIC_EXACT:
        return True
    if any(marker in n for marker in _GENERIC_MARKERS):
        return True
    return is_collective_descriptor(n)

# ---------------------------------------------------------------------------
# Junk-token filter — deterministic first line of defence against non-names
# ("888", "-", "CMD", "F6", "GOD user", blank/unicode tokens). Applied at the
# CREATE decision only, so it never blocks linking to an existing entity.
# ---------------------------------------------------------------------------

_JUNK_EXACT = frozenset({
    "cmd", "meta", "god", "god user", "user", "admin", "root", "system",
    "data", "info", "misc", "test", "example", "null", "sample", "temp",
    "-", "--", "n/a", "na", "tbd", "todo", "xxx", "unknown",
})


def is_junk_name(value) -> bool:
    """True if the token is clearly not a real named entity (create-gate)."""
    n = _norm_name(value)
    if len(n) < 3:                       # too short to be a real name (kills 'F6', '-')
        return True
    if n in _JUNK_EXACT:
        return True
    letters = sum(c.isalpha() for c in n)
    if letters < 2:                      # needs real alphabetic content (kills '888', '0x1')
        return True
    return False


# ---------------------------------------------------------------------------
# Known-legitimate software allowlist — forces kind=tool so widely-used, benign
# or dual-use software (and, notably, AI products) is never created as Malware.
# ---------------------------------------------------------------------------

LEGIT_SOFTWARE = frozenset({
    # Remote access / RMM
    "openvpn", "openssh", "ssh", "anydesk", "teamviewer", "radmin", "radmin vpn",
    "ultraviewer", "psexec", "paexec", "putty", "rustdesk", "splashtop",
    "connectwise", "screenconnect", "atera", "syncro", "logmein", "remote utilities",
    "litemanager", "dwservice", "meshcentral", "ngrok",
    # Utilities / dev / admin
    "nmap", "nuclei", "masscan", "rclone", "winrar", "7zip", "7-zip", "curl", "wget",
    "powershell", "node", "node.js", "nodejs", "bun", "deno", "python", "git",
    "openssl", "keepass", "keepassxc", "bitlocker", "softperfect network scanner",
    "cobian backup", "pandora fms", "advanced ip scanner", "angry ip scanner",
    "process hacker", "sysinternals", "notepad++", "filezilla", "winscp",
    # AI products / LLMs (frequently mis-listed as "malware" in reports)
    "deepseek", "qwen", "kimi", "minimax", "glm", "claude", "claude code",
    "codex", "chatgpt", "gpt-4", "gpt-4o", "gemini", "copilot", "github copilot",
    "llama", "mistral", "grok", "perplexity",
})
_LEGIT_SOFTWARE_KEYS = frozenset(_dedup_key(s) for s in LEGIT_SOFTWARE)


def is_known_legit_software(value) -> bool:
    """True if the name matches a known legitimate/dual-use software (-> Tool)."""
    return _dedup_key(value) in _LEGIT_SOFTWARE_KEYS


# Infrastructure/platform/runtime/OS software: this is almost always the VICTIM's
# affected product, NOT an adversary tool. It must never be created as a Tool.
INFRA_SOFTWARE = frozenset({
    "wordpress", "drupal", "joomla", "magento", "typo3", "sharepoint",
    "microsoft sharepoint", "exchange", "microsoft exchange", "outlook",
    "office", "office 365", "microsoft 365", "microsoft office",
    "apache", "apache http server", "httpd", "nginx", "tomcat", "apache tomcat",
    "iis", "microsoft iis", "php", "asp.net", "java", "jakarta",
    "mysql", "mariadb", "postgresql", "postgres", "mssql", "sql server",
    "mongodb", "redis", "elasticsearch", "oracle database",
    "node.js", "nodejs", "node", "deno", "bun", "jenkins", "gitlab", "github",
    "windows", "windows server", "linux", "ubuntu", "debian", "centos",
    "red hat", "rhel", "vmware", "vmware esxi", "esxi", "vcenter", "docker",
    "kubernetes", "wordpress plugin", "ptc windchill", "pandora fms",
    "citrix", "citrix netscaler", "fortinet", "fortios", "confluence", "jira",
})
_INFRA_SOFTWARE_KEYS = frozenset(_dedup_key(s) for s in INFRA_SOFTWARE)


def is_infra_software(value) -> bool:
    """True if the name is victim infrastructure/platform (never an adversary Tool)."""
    return _dedup_key(value) in _INFRA_SOFTWARE_KEYS


# Protocols / generic utilities / messengers: too generic to be useful Tool nodes.
# NOTE: genuine adversary tools (nmap, metasploit, psexec, anydesk, mimikatz,
# cobalt strike, advanced ip scanner, process hacker, plink...) are intentionally
# NOT here — they stay as Tools.
TOOL_NOISE = frozenset({
    # protocols / services
    "rdp", "ssh", "sftp", "scp", "ftp", "ftps", "telnet", "vnc", "smb", "winrm",
    "http", "https", "dns", "tcp", "udp", "icmp", "snmp", "ldap", "kerberos", "wmi",
    # shells / interpreters / runtimes (LOLBins but noise as entities)
    "curl", "wget", "python", "python3", "perl", "ruby", "bash", "sh", "zsh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "vbscript", "jscript",
    # archivers
    "7-zip", "7zip", "7z", "winrar", "rar", "zip", "tar", "gzip", "unzip",
    # messengers / c2 comms apps
    "telegram", "tox", "qtox", "session", "signal", "whatsapp", "discord",
    "jabber", "xmpp", "tor", "tor browser",
    # misc generic
    "ollama", "notepad", "notepad++", "wordpad", "kali", "kali linux", "kali365",
    "browser", "web browser", "email", "outlook",
})
_TOOL_NOISE_KEYS = frozenset(_dedup_key(s) for s in TOOL_NOISE)


def is_tool_noise(value) -> bool:
    """True if the name is a protocol/generic utility/messenger (skip as a Tool)."""
    return _dedup_key(value) in _TOOL_NOISE_KEYS


# Cryptominers: these are malware (resource-exploitation), not tools.
MINER_SOFTWARE = frozenset({
    "xmrig", "xmr-stak", "xmrig-proxy", "minerd", "cgminer", "bfgminer", "nicehash",
    "nicehash miner", "phoenixminer", "lolminer", "gminer", "teamredminer",
    "cpuminer", "coinminer", "cryptominer", "monero miner", "t-rex miner", "nbminer",
})
_MINER_KEYS = frozenset(_dedup_key(s) for s in MINER_SOFTWARE)


def is_miner(value) -> bool:
    """True if the name is a cryptominer (classify as Malware, not Tool)."""
    return _dedup_key(value) in _MINER_KEYS


# Defensive security products. These belong to the VICTIM's environment — they
# get disabled/bypassed by attackers (an ATT&CK technique), they are not
# adversary tooling. Creating them as Tools implies the opposite of the truth.
SECURITY_PRODUCTS = frozenset({
    "windows defender", "microsoft defender", "defender", "microsoft defender atp",
    "defender for endpoint", "quick heal", "kaspersky", "bitdefender", "eset",
    "eset nod32", "sophos", "crowdstrike", "crowdstrike falcon", "falcon sensor",
    "sentinelone", "symantec", "norton", "mcafee", "trend micro", "avast", "avg",
    "malwarebytes", "trellix", "fireeye", "carbon black", "vmware carbon black",
    "cylance", "f-secure", "webroot", "sucuri", "wordfence", "cortex xdr",
    "palo alto cortex", "checkpoint harmony", "windows firewall", "applocker",
    "windows smartscreen", "gatekeeper", "amsi", "sentinel one",
})
_SECURITY_PRODUCT_KEYS = frozenset(_dedup_key(s) for s in SECURITY_PRODUCTS)


def is_security_product(value) -> bool:
    """True if the name is a defensive security product (never adversary tooling)."""
    return _dedup_key(value) in _SECURITY_PRODUCT_KEYS


# Consumer AI/LLM assistants and general-purpose apps. Mentioned constantly in
# 2026 reporting but they are not adversary tooling; creating Tool nodes for them
# floods the graph. Purpose-built offensive AI (WormGPT, FraudGPT, PentestGPT)
# is deliberately NOT here — that IS adversary tooling.
CONSUMER_SOFTWARE_NOISE = frozenset({
    # AI assistants / models / services
    "chatgpt", "openai", "gpt-4", "gpt-4o", "gpt-4o-mini", "gpt-5", "gpt4",
    "claude", "claude code", "anthropic", "copilot", "github copilot",
    "microsoft copilot", "gemini", "google gemini", "bard", "perplexity",
    "midjourney", "stable diffusion", "dall-e", "whisper", "openai whisper",
    "elevenlabs", "cursor", "deepseek", "qwen", "llama", "grok", "notebooklm",
    # general-purpose consumer/desktop apps
    "calibre", "mp3tag", "abbyy finereader", "overwolf", "opencamera",
    "vlc", "spotify", "steam", "zoom", "skype", "dropbox", "google drive",
    "onedrive", "microsoft office", "office 365", "excel", "word", "adobe reader",
    # installer/packaging frameworks (abused, but not the adversary's tool)
    "inno setup", "squirrel", "nsis", "installshield", "advanced installer",
})
_CONSUMER_NOISE_KEYS = frozenset(_dedup_key(s) for s in CONSUMER_SOFTWARE_NOISE)


def is_consumer_software_noise(value) -> bool:
    """True if the name is a consumer AI/general app (skip: not adversary tooling)."""
    return _dedup_key(value) in _CONSUMER_NOISE_KEYS


# Real-world criminal / paramilitary organisations. They appear in intelligence
# reporting but they are not cyber intrusion sets, and minting them as
# Threat-Actor entities pollutes the threat taxonomy.
NON_CYBER_ORGS = frozenset({
    "cartel de jalisco nueva generacion", "cartel de jalisco nueva generacién",
    "cjng", "sinaloa cartel", "cartel de sinaloa", "comando vermelho",
    "primeiro comando da capital", "pcc", "viv ansanm", "gulf cartel",
    "los zetas", "ms-13", "mara salvatrucha", "black axe", "yakuza", "triad",
})
_NON_CYBER_ORG_KEYS = frozenset(_dedup_key(s) for s in NON_CYBER_ORGS)

# Campaign/operation naming pattern — an operation is a Campaign, not an actor.
_OPERATION_RE = re.compile(r"^\s*(operation|op\.?)\s+\S+", re.IGNORECASE)

# Corporate-entity markers that reveal a company was named as a threat actor.
_COMPANY_ACTOR_MARKERS = (
    "co. ltd", "co.,ltd", "co ltd", "company limited", "network technology",
    "technology co", "technologies co", "information technology co",
    "pvt. ltd", "pvt ltd", "private limited", "gmbh", "s.a. de c.v.",
)





def is_non_actor_name(value) -> bool:
    """True if the name must never become a Threat-Actor / Intrusion-Set.

    Catches the three actor failure modes observed in measurement: real-world
    criminal organisations, campaign/operation names, and companies.
    """
    raw = str(value or "").strip()
    if not raw:
        return True
    if _dedup_key(raw) in _NON_CYBER_ORG_KEYS:
        return True
    if _OPERATION_RE.match(raw):
        return True
    low = _norm_name(raw)
    if any(marker in low for marker in _COMPANY_ACTOR_MARKERS):
        return True
    # A legal-form suffix as the final token is a strong company signal
    # (e.g. "Brightsoft Inc", "Qv Technology Ltd") — but never "… Group".
    tokens = low.replace(",", " ").split()
    if len(tokens) > 1 and tokens[-1].strip(".") in _LEGAL_FORM_SUFFIX:
        return True
    return False

# ---------------------------------------------------------------------------
# ACTOR signals — the inverse of is_non_actor_name.
#
# Measured failure: names correctly extracted as threat actors were moved into
# `victims` by the critic pass and would then have been created as victim
# organisations ("FulcrumSec", "Global Secret Group", "Business Data Leaks",
# "Lego Resistance Front"). Operating a leak site, or self-branding as an
# extortion crew, is ATTACKER behaviour. These predicates are deterministic and
# used to REFUSE such a reclassification.
# ---------------------------------------------------------------------------

# Self-branding that only an adversary uses. Deliberately excludes bare
# "group"/"team" — victim organisations are routinely called "… Group"
# ("Calder Group", "Brentmoor Group"), so those alone prove nothing.
_ADVERSARY_BRAND_MARKERS = (
    "data leak", "data leaks", "dataleak", "leak site", "leaksite",
    "ransomware", "ransom team", "ransom group", "extortion", "hacktivist",
    "cyber team", "cyber army", "cyber crew", "hack team", "hacking team",
    "hackers", "hacker group", "cyber caliphate", "cyber fighters",
)


def is_adversary_brand_name(value) -> bool:
    """True if the name is adversary self-branding and can never be a victim.

    Used to veto an actor -> victim reclassification: no breached organisation
    is legally named "Business Data Leaks".
    """
    low = _norm_name(value)
    if not low:
        return False
    return any(marker in low for marker in _ADVERSARY_BRAND_MARKERS)


# Phrases that mark the thing they FOLLOW as a leak-site / extortion-blog
# operator. Position matters: "<X> Data Leak Site" means X runs the site,
# whereas an organisation merely listed *on* someone's leak site is a victim.
_LEAK_SITE_PHRASE = (
    r"(?:data\s*leaks?\s*(?:site|blog|portal|page)|dedicated\s*leak\s*site|"
    r"leaks?\s*(?:site|blog|portal)|extortion\s*(?:site|blog|page)|"
    r"ransomware\s*(?:blog|site)|sham(?:e|ing)\s*site|onion\s*(?:site|blog)|"
    r"victim\s*blog|tor\s*(?:site|blog)|has\s*published\s*a\s*new\s*victim|"
    r"claimed\s*responsibility|published\s*(?:the\s*)?victims?)"
)
_LEAK_SITE_RE_CACHE: dict = {}

# Between two significant tokens of a name the source may carry a couple of
# filler words the detection dropped ("Meridian HealthCare **of** Fairview City"
# vs the detected "Meridian HealthCare of Fairview City Inc."). Haystacks are
# punctuation-stripped, so words are single-space separated.
_NAME_GAP = r"(?: \w+){0,2} "


def _name_regex_forms(name) -> list:
    """Regex fragments that match `name` in a normalised haystack.

    Two forms: the name verbatim, and its significant tokens with small gaps
    allowed. The second exists because detections routinely carry a corporate
    suffix the prose omits ("… Fairview City Inc." vs "… Fairview City"), and an
    exact-only match would silently fail on every such organisation.
    """
    n = _grounding_haystack(name)
    if not n:
        return []
    forms = [re.escape(n)]
    tokens = [t for t in n.split()
              if t not in _ORG_SUFFIX and t not in _ORG_STOP
              and t not in _STOPWORD_TOKENS]
    if len(tokens) >= 2 and " ".join(tokens) != n:
        forms.append(_NAME_GAP.join(re.escape(t) for t in tokens))
    return forms


def is_leak_site_operator(name, *haystacks) -> bool:
    """True when the source text presents `name` as running a leak site / blog.

    Deliberately positional — the leak-site phrase must FOLLOW the name — so an
    organisation listed on someone else's leak site is not mistaken for its
    operator. Also matches the leak-post title convention "<operator> Blog".
    """
    key = _grounding_haystack(name)
    if not key:
        return False
    pattern = _LEAK_SITE_RE_CACHE.get(key)
    if pattern is None:
        forms = _name_regex_forms(name)
        if not forms:
            return False
        pattern = re.compile(
            "(?:" + "|".join(forms) + r")\s+(?:" + _LEAK_SITE_PHRASE + r"|blog\s*$)"
        )
        if len(_LEAK_SITE_RE_CACHE) < 512:
            _LEAK_SITE_RE_CACHE[key] = pattern
    for hay in haystacks:
        hay = _grounding_haystack(hay)
        if hay and pattern.search(hay):
            return True
    return False


# Breach phrasing that genuinely marks an organisation as a victim. Used to
# demand positive evidence before an actor is reclassified as a victim.
_VICTIM_EVENT = (
    r"(?:data\s*breach|breach(?:ed|es)?|incident|intrusion|compromis(?:e|ed)|"
    r"leak(?:ed)?|hack(?:ed)?|attack(?:ed)?|ransomware\s*attack|exfiltrat\w+)"
)
_VICTIM_LEAD = (
    r"(?:new\s*victim\s*:?|victim\s*:?|targeted|targeting|breached|hit\s*by|"
    r"attacked|impacted|affected|claims?\s*(?:to\s*have\s*)?breached|"
    r"published\s*a\s*new\s*victim\s*:?)"
)
_VICTIM_CTX_CACHE: dict = {}


def has_victim_context(name, *haystacks) -> bool:
    """True when the source text presents `name` as a breached organisation.

    Two shapes, both bounded to a short window so an unrelated sentence nearby
    cannot create a false positive:
      - "<name> ... reports a data breach"   (name precedes the event)
      - "new victim: <name>" / "targeted <name>"  (lead-in precedes the name)
    """
    key = _grounding_haystack(name)
    if not key:
        return False
    pair = _VICTIM_CTX_CACHE.get(key)
    if pair is None:
        forms = _name_regex_forms(name)
        if not forms:
            return False
        alt = "(?:" + "|".join(forms) + ")"
        after = re.compile(alt + r".{0,60}?" + _VICTIM_EVENT)
        before = re.compile(_VICTIM_LEAD + r".{0,40}?" + alt)
        pair = (after, before)
        if len(_VICTIM_CTX_CACHE) < 512:
            _VICTIM_CTX_CACHE[key] = pair
    for hay in haystacks:
        hay = _grounding_haystack(hay)
        if not hay:
            continue
        if pair[0].search(hay) or pair[1].search(hay):
            return True
    return False

