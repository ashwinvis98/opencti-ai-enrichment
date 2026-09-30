"""External reference retrieval, replacing search grounding.

The connector fetches the referenced article itself and puts its text in
the prompt. That costs no grounding quota, is deterministic, and works on
open sources.

SECURITY: these URLs come from third-party feed data and this connector
runs INSIDE the platform network, so a hostile reference is an SSRF vector.
Every URL and EVERY REDIRECT HOP must be http(s) resolving exclusively to
public addresses. Auth-gated portals are skipped because fetching them
returns a login page, which is worse than nothing."""
import html as _html
import ipaddress
import re
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# External reference fetching — replaces Google Search grounding.
#
# We fetch the referenced article ourselves and put its text in the prompt. This
# costs no Gemini grounding quota, is deterministic, and works on open sources.
#
# SECURITY: these URLs arrive from third-party feed data and this connector runs
# INSIDE the OpenCTI docker network, so a hostile reference could try to make us
# fetch internal services or cloud metadata (SSRF). Every URL — and every
# redirect hop — is therefore validated to be http(s) on a PUBLIC IP address.
# ---------------------------------------------------------------------------

# Portals that require authentication: fetching them yields a login page, which
# is worse than nothing (it would pollute the prompt with irrelevant text).
GATED_REF_DOMAINS = (
    "app.recordedfuture.com", "recordedfuture.com/live", "otx.alienvault.com",
    "portal.", "login.", "signin.", "account.", "my.", "dashboard.",
    "app.any.run", "intelx.io", "virustotal.com/gui", "mandiant.com/advantage",
    "services.google.com", "intel471.com", "flashpoint.io", "zerofox.com",
    "crowdstrike.com/falcon", "threatconnect.com", "anomali.com",
    "linkedin.com", "twitter.com", "x.com", "facebook.com", "t.me",
)

# Only textual content is useful; anything else (pdf/zip/images) is skipped since
# we have no parser for it and would inject binary noise into the prompt.
_FETCHABLE_CONTENT_TYPES = ("text/html", "text/plain", "application/json",
                            "application/xml", "text/xml", "application/xhtml")

_SCRIPT_STYLE_RE = re.compile(r"<(script|style|noscript|svg|head)\b.*?</\1>",
                              re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_MULTI_NL_RE = re.compile(r"\n{3,}")


def is_gated_ref(url: str) -> bool:
    """True if the URL is an auth-gated portal (fetching would return a login page)."""
    u = (url or "").lower()
    return any(d in u for d in GATED_REF_DOMAINS)


def _is_public_host(host: str) -> bool:
    """Resolve a hostname and require every address to be public (anti-SSRF)."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:  # noqa: BLE001
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False
    return True


def is_safe_ref_url(url: str) -> bool:
    """Allow only http(s) URLs whose host resolves exclusively to public IPs."""
    try:
        p = urlparse(url or "")
    except Exception:  # noqa: BLE001
        return False
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    return _is_public_host(p.hostname)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validate every redirect target — a public URL may redirect to an internal one."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        if not is_safe_ref_url(newurl):
            raise urllib.error.URLError(f"unsafe redirect target: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def html_to_text(raw: str) -> str:
    """Crude but dependency-free HTML -> text extraction."""
    text = _SCRIPT_STYLE_RE.sub(" ", raw or "")
    text = re.sub(r"<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", text, flags=re.IGNORECASE)
    text = _TAG_RE.sub(" ", text)
    text = _html.unescape(text)
    text = _WS_RE.sub(" ", text)
    text = "\n".join(line.strip() for line in text.split("\n"))
    return _MULTI_NL_RE.sub("\n\n", text).strip()


def fetch_reference_text(url: str, timeout: int = 10, max_bytes: int = 400_000) -> "str | None":
    """Fetch a reference URL and return readable text, or None if not usable."""
    if not is_safe_ref_url(url) or is_gated_ref(url):
        return None
    req = urllib.request.Request(
        url,
        headers={
            # Identify ourselves honestly; some sites block unknown clients.
            "User-Agent": "OpenCTI-AI-Enrichment/1.0 (+threat-intel enrichment)",
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1",
        },
    )
    opener = urllib.request.build_opener(_SafeRedirectHandler)
    try:
        with opener.open(req, timeout=timeout) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if not any(t in ctype for t in _FETCHABLE_CONTENT_TYPES):
                return None
            raw = resp.read(max_bytes)
    except Exception:  # noqa: BLE001
        return None
    charset = "utf-8"
    if "charset=" in ctype:
        charset = ctype.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
    try:
        decoded = raw.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        decoded = raw.decode("utf-8", errors="replace")
    text = html_to_text(decoded)
    return text or None

