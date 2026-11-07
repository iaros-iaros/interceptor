"""Passive findings: the obvious security smells, read off a flow as it finalises.

**Passive only, on purpose.** Nothing here sends a byte the application did not
already send -- it only reads what went past. That is the whole safety story: an
active scanner probes, mutates and can break a target, and is a different tool with
a different blast radius. This is `grep` over your own traffic, so it is always safe
to leave on.

**First-sight dedup is the addon's job, not this file's.** `passive()` reports every
smell it sees on one flow, each paired with a *key*; the addon keeps the set of
(code, key) it has already surfaced and tags a flow only with the codes new to it. A
single page load is 300 flows from one host, so the same missing header on every one
of them would bury the finding under its own repetition. The key decides the grain:
`host` for a per-site header, `host:cookie` for a per-cookie flag, so each distinct
problem is reported once and a genuinely new one still shows.

Every code has a one-line explanation in EXPLAIN, which the UI shows on the flow and
`~meta <code>` matches as a scope.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

from mitmproxy import http

# A JWT starts with the base64url of `{"` -- `eyJ` -- then two more dot-separated
# base64url segments. Specific enough that a match is a token, not prose.
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Query parameters whose value does not belong in a URL: URLs land in logs, in
# Referer headers and in browser history, none of which should hold a credential.
_SECRET_PARAMS = {
    "token", "access_token", "refresh_token", "api_key", "apikey", "key",
    "secret", "password", "passwd", "pwd", "auth", "session", "sid", "jwt",
}

EXPLAIN = {
    "missing-hsts": "No Strict-Transport-Security header, so a browser can be downgraded to http.",
    "missing-csp": "HTML served without a Content-Security-Policy, the main defence against injected script.",
    "missing-frame-protection": "No X-Frame-Options and no frame-ancestors, so the page can be framed for clickjacking.",
    "missing-nosniff": "No X-Content-Type-Options: nosniff, so the browser may MIME-sniff the body into a script.",
    "cookie-insecure": "A cookie set over https without Secure, so it can leak over a downgraded http request.",
    "cookie-no-httponly": "A cookie without HttpOnly, so script on the page can read it.",
    "cookie-no-samesite": "A cookie without SameSite, so it rides along on cross-site requests (CSRF).",
    "cors-wildcard-credentials": "Access-Control-Allow-Origin: * together with credentials — any origin can read the response.",
    "cors-origin-reflected": "The request Origin is reflected into Access-Control-Allow-Origin with credentials — same effect, harder to spot.",
    "jwt-alg-none": "A JWT with alg:none — unsigned, so anyone can forge its claims.",
    "secret-in-url": "A credential-looking query parameter in the URL, where it lands in logs and history.",
    "basic-auth": "HTTP Basic auth — the credentials are base64, not encrypted; only the TLS layer protects them.",
    "plain-http-auth": "Credentials (Authorization or Cookie) sent over plain http, in the clear.",
    "server-version": "A Server or X-Powered-By header with a version, which hands an attacker the exact build to look up.",
    "directory-listing": "An auto-generated directory listing, which exposes files that were not meant to be browsed.",
}


def _ctype(resp: http.Response) -> str:
    return resp.headers.get("content-type", "").split(";")[0].strip().lower()


def _alg_none(token: str) -> bool:
    """True when a JWT's header declares alg:none. Padding is restored because
    base64url drops it; a malformed header is simply not a finding."""
    head = token.split(".", 1)[0]
    try:
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
        return str(json.loads(raw).get("alg", "")).lower() == "none"
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False


def _body_head(resp: http.Response, n: int = 8192) -> str:
    """The first n chars of the body as text, for a cheap substring look. Never
    raises: a body that will not decode is just not matched."""
    try:
        return (resp.get_text(strict=False) or "")[:n]
    except (ValueError, TypeError):
        return ""


def passive(flow: http.HTTPFlow) -> list[tuple[str, str]]:
    """Every smell on this flow, each as (code, dedup-key). Never raises: a check
    that cannot run is a check that does not fire, never an exception on the
    proxy's event loop."""
    try:
        return _passive(flow)
    except Exception:  # pragma: no cover -- a finding must never take the proxy down
        return []


def _passive(flow: http.HTTPFlow) -> list[tuple[str, str]]:
    req, resp = flow.request, flow.response
    host = req.host
    https = req.scheme == "https"
    out: list[tuple[str, str]] = []

    # ---- request side (runs even without a response) -----------------------
    for name in req.query.keys():
        if name.lower() in _SECRET_PARAMS:
            out.append(("secret-in-url", f"{host}:{name.lower()}"))

    authz = req.headers.get("authorization", "")
    if authz.lower().startswith("basic "):
        out.append(("basic-auth", host))
    if not https and (authz or req.headers.get("cookie")):
        out.append(("plain-http-auth", host))

    # A forged-claims JWT is worth flagging wherever it travels.
    for value in req.headers.values():
        for token in _JWT.findall(value):
            if _alg_none(token):
                out.append(("jwt-alg-none", token[:16]))

    if resp is None:
        return out

    code = resp.status_code
    ok = 200 <= code < 300
    ctype = _ctype(resp)
    html = ctype in ("text/html", "application/xhtml+xml")
    csp = resp.headers.get("content-security-policy", "").lower()

    # ---- response headers --------------------------------------------------
    if https and (200 <= code < 400) and "strict-transport-security" not in resp.headers:
        out.append(("missing-hsts", host))
    if ok and html and not csp:
        out.append(("missing-csp", host))
    if ok and html and "x-frame-options" not in resp.headers and "frame-ancestors" not in csp:
        out.append(("missing-frame-protection", host))
    if ok and resp.raw_content and resp.headers.get(
            "x-content-type-options", "").lower() != "nosniff":
        out.append(("missing-nosniff", host))

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    origin = req.headers.get("origin", "")
    if acao == "*" and acac:
        out.append(("cors-wildcard-credentials", host))
    elif origin and acao == origin and acac:
        out.append(("cors-origin-reflected", host))

    for cookie in resp.headers.get_all("set-cookie"):
        name = cookie.split("=", 1)[0].strip()
        attrs = cookie.lower()
        if https and "secure" not in attrs:
            out.append(("cookie-insecure", f"{host}:{name}"))
        if "httponly" not in attrs:
            out.append(("cookie-no-httponly", f"{host}:{name}"))
        if "samesite" not in attrs:
            out.append(("cookie-no-samesite", f"{host}:{name}"))
        for token in _JWT.findall(cookie):
            if _alg_none(token):
                out.append(("jwt-alg-none", token[:16]))

    for header in ("server", "x-powered-by"):
        value = resp.headers.get(header, "")
        if re.search(r"\d+\.\d+", value):
            out.append(("server-version", f"{host}:{header}"))

    if html and "Index of /" in _body_head(resp):
        out.append(("directory-listing", f"{host}:{req.path.split('?')[0]}"))

    return out
