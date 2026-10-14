#!/usr/bin/env python3
"""End-to-end test for keycloak-altcha. Python 3 standard library only.

full  : creates a throwaway realm through the Admin REST API (user, client, flow copies with the
        two ALTCHA authenticators bound, brute-force detection on), drives the real browser
        login and forgot-password flows over HTTP, including parallel submits and a passkey
        post, and deletes the realm afterwards (unless --keep).
smoke : read-only against an existing realm: loads the login page, checks a challenge is
        issued, solves it and submits it. Works with the test theme and with Keycloakify
        themes (challenge read from the kcContext object).

  python3 src/it/e2e.py full --base-url http://127.0.0.1:8080 --admin-user admin --admin-password admin
  python3 src/it/e2e.py smoke --base-url https://sso.example.org --realm myrealm \\
      --client-id account-console --redirect-uri https://sso.example.org/realms/myrealm/account/ \\
      [--username u --password p] [--resolve sso.example.org:443:192.0.2.10]
"""

import argparse
import base64
import hashlib
import html
import http.cookiejar
import json
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ALTCHA_FAILED = ("Verification failed", "驗證未通過")
INVALID_CREDENTIALS = ("Invalid username or password", "使用者名稱或密碼無效")


# ---------------------------------------------------------------- ALTCHA, as the widget does it

def solve(challenge_json):
    """Return the widget's payload for an ALTCHA v2 SHA-256 challenge."""
    p = json.loads(challenge_json)["parameters"]
    assert p["algorithm"] == "SHA-256", p
    nonce, salt = bytes.fromhex(p["nonce"]), bytes.fromhex(p["salt"])
    for counter in range(1 << 32):
        key = salt + nonce + counter.to_bytes(4, "big")
        for _ in range(max(1, p["cost"])):
            key = hashlib.sha256(key).digest()
        derived = key[: p["keyLength"]].hex()
        if derived.startswith(p["keyPrefix"]):
            body = {"challenge": {"parameters": p}, "solution": {"counter": counter, "derivedKey": derived}}
            return base64.b64encode(json.dumps(body).encode()).decode()
    raise AssertionError("no solution")


def tamper(payload):
    body = json.loads(base64.b64decode(payload))
    key = body["solution"]["derivedKey"]
    body["solution"]["derivedKey"] = key[:-1] + ("0" if key[-1] != "0" else "1")
    return base64.b64encode(json.dumps(body).encode()).decode()


# ---------------------------------------------------------------- HTTP

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def install_resolve(entries):
    """curl-style --resolve host:port:ip, applied to every connection this process opens."""
    table = {}
    for e in entries or []:
        host, port, ip = e.split(":", 2)
        table[(host, int(port))] = ip.strip("[]")
    if table:
        original = socket.create_connection

        def create_connection(address, *args, **kwargs):
            return original((table.get(address, address[0]), address[1]), *args, **kwargs)

        socket.create_connection = create_connection


class LoopbackIsSecure(http.cookiejar.DefaultCookiePolicy):
    """Browsers send Secure cookies to http://localhost; Keycloak relies on that in dev mode."""

    def return_ok_secure(self, cookie, request):
        host = urllib.parse.urlparse(request.full_url).hostname
        return host in ("localhost", "127.0.0.1", "::1") or super().return_ok_secure(cookie, request)


class Browser:
    """Cookie jar + no automatic redirects, like a form post from a real browser tab."""

    def __init__(self, insecure=False):
        ctx = ssl._create_unverified_context() if insecure else None
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(LoopbackIsSecure())),
            urllib.request.HTTPSHandler(context=ctx),
            NoRedirect())

    def request(self, url, form=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(url, data=data, headers={"Accept-Language": "en"})
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status, r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")


class Page:
    """A rendered login page: the plain test theme, or a Keycloakify page (kcContext)."""

    def __init__(self, status, headers, body):
        self.status, self.location, self.body = status, headers.get("Location"), body

    def _kc(self, key):
        m = re.search(r'"%s"\s*:\s*("(?:[^"\\]|\\.)*")' % key, self.body)
        return json.loads(m.group(1)) if m else None

    @property
    def challenge(self):
        m = re.search(r'<pre id="altcha-challenge">(.*?)</pre>', self.body, re.S)
        value = html.unescape(m.group(1)).strip() if m else self._kc("altchaChallenge")
        return value or None

    @property
    def action(self):
        m = re.search(r'<form[^>]*\saction="([^"]+)"', self.body)
        return html.unescape(m.group(1)) if m else self._kc("loginAction")

    @property
    def reset_url(self):
        m = re.search(r'href="([^"]*login-actions/reset-credentials[^"]*)"', self.body)
        return html.unescape(m.group(1)) if m else self._kc("loginResetCredentialsUrl")

    @property
    def message(self):
        m = re.search(r'<p id="message"[^>]*>(.*?)</p>', self.body, re.S)
        if m:
            return html.unescape(m.group(1))
        m = re.search(r'"message"\s*:\s*\{[^{}]*?"summary"\s*:\s*("(?:[^"\\]|\\.)*")', self.body)
        return json.loads(m.group(1)) if m else ""

    def code(self):
        if self.status in (302, 303) and self.location:
            return urllib.parse.parse_qs(urllib.parse.urlparse(self.location).query).get("code", [None])[0]
        return None


def auth_url(base, realm, client_id, redirect_uri):
    q = urllib.parse.urlencode({"client_id": client_id, "redirect_uri": redirect_uri,
                                "response_type": "code", "scope": "openid", "ui_locales": "en",
                                "state": secrets.token_hex(8), "nonce": secrets.token_hex(8)})
    return f"{base}/realms/{realm}/protocol/openid-connect/auth?{q}"


# ---------------------------------------------------------------- checks

class Checks:
    def __init__(self):
        self.passed, self.failed = 0, 0

    def check(self, name, ok, detail=""):
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -- {detail}"), flush=True)
        if ok:
            self.passed += 1
        else:
            self.failed += 1

    def summary(self):
        print(f"SUMMARY: {self.passed} passed, {self.failed} failed")
        return 1 if self.failed else 0


def is_altcha_failure(page):
    return page.code() is None and any(t in page.message for t in ALTCHA_FAILED)


def is_invalid_credentials(page):
    return page.code() is None and any(t in page.message for t in INVALID_CREDENTIALS)


def describe(page):
    return f"status={page.status} location={page.location} message={page.message!r}"


# ---------------------------------------------------------------- Admin REST API

class Admin:
    def __init__(self, base, user, password, insecure=False):
        self.base = base
        self.ctx = ssl._create_unverified_context() if insecure else None
        token = self._call("POST", f"{base}/realms/master/protocol/openid-connect/token",
                           form={"grant_type": "password", "client_id": "admin-cli",
                                 "username": user, "password": password})
        self.token = token["access_token"]

    def _call(self, method, url, body=None, form=None):
        headers = {}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if getattr(self, "token", None):
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
            raw = r.read()
            if r.headers.get("Location") and not raw:
                return r.headers["Location"].rsplit("/", 1)[-1]
            return json.loads(raw) if raw else None

    def __call__(self, method, path, body=None):
        return self._call(method, f"{self.base}/admin/realms{path}", body)


def q(s):
    return urllib.parse.quote(s, safe="")


def swap_execution(admin, realm, flow, old, new):
    """Replace provider OLD with NEW at the same level and position, REQUIRED. Returns the new id."""
    executions = admin("GET", f"/{realm}/authentication/flows/{q(flow)}/executions")
    parents = {0: flow}
    for e in executions:
        if e.get("authenticationFlow"):
            parents[e["level"] + 1] = e["displayName"]
        if e.get("providerId") == old:
            target = e
            break
    else:
        raise AssertionError(f"{old} not found in {flow}")
    parent = parents[target["level"]]
    admin("DELETE", f"/{realm}/authentication/executions/{target['id']}")
    new_id = admin("POST", f"/{realm}/authentication/flows/{q(parent)}/executions/execution", {"provider": new})
    rep = next(e for e in admin("GET", f"/{realm}/authentication/flows/{q(parent)}/executions") if e["id"] == new_id)
    rep["requirement"] = "REQUIRED"
    admin("PUT", f"/{realm}/authentication/flows/{q(parent)}/executions", rep)
    for _ in range(target["index"] + 10):  # new executions land last among their siblings
        rep = next(e for e in admin("GET", f"/{realm}/authentication/flows/{q(flow)}/executions") if e["id"] == new_id)
        if rep["index"] <= target["index"]:
            break
        admin("POST", f"/{realm}/authentication/executions/{new_id}/raise-priority", {})
    return new_id


def setup_realm(admin, realm, theme, redirect_uri):
    admin("POST", "", {
        "realm": realm, "enabled": True, "loginTheme": theme, "resetPasswordAllowed": True,
        "eventsEnabled": True, "bruteForceProtected": True})
    user_id = admin("POST", f"/{realm}/users", {
        "username": "tester", "email": "tester@example.org", "emailVerified": True,
        "firstName": "Test", "lastName": "User", "enabled": True,
        "credentials": [{"type": "password", "value": "Passw0rd!", "temporary": False}]})
    admin("POST", f"/{realm}/clients", {
        "clientId": "altcha-e2e", "publicClient": True, "standardFlowEnabled": True,
        "redirectUris": [redirect_uri]})
    admin("POST", f"/{realm}/authentication/flows/browser/copy", {"newName": "browser altcha"})
    login_exec = swap_execution(admin, realm, "browser altcha",
                                "auth-username-password-form", "altcha-username-password-form")
    admin("POST", f"/{realm}/authentication/flows/{q('reset credentials')}/copy",
          {"newName": "reset credentials altcha"})
    swap_execution(admin, realm, "reset credentials altcha",
                   "reset-credentials-choose-user", "altcha-reset-credential-choose-user")
    admin("PUT", f"/{realm}", {"browserFlow": "browser altcha",
                               "resetCredentialsFlow": "reset credentials altcha"})
    return login_exec, user_id


# ---------------------------------------------------------------- scenarios

def run_full(args):
    base = args.base_url.rstrip("/")
    realm, redirect_uri = args.realm, "http://e2e.invalid/callback"
    admin = Admin(base, args.admin_user, args.admin_password, args.insecure)
    try:
        admin("GET", f"/{realm}")
        sys.exit(f"realm {realm!r} already exists; delete it or pass another --realm")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    c = Checks()
    try:
        login_exec, user_id = setup_realm(admin, realm, args.login_theme, redirect_uri)
        scenarios(c, base, realm, admin, login_exec, user_id, redirect_uri, args.insecure)
    finally:
        if not args.keep:
            admin("DELETE", f"/{realm}")
    return c.summary()


def scenarios(c, base, realm, admin, login_exec, user_id, redirect_uri, insecure):
    url = auth_url(base, realm, "altcha-e2e", redirect_uri)

    def failures():
        return admin("GET", f"/{realm}/attack-detection/brute-force/users/{user_id}")["numFailures"]

    def open_login():
        b = Browser(insecure)
        return b, Page(*b.request(url))

    def post(b, page, password="Passw0rd!", payload=None, username="tester"):
        form = {"username": username, "password": password}
        if payload is not None:
            form["altcha"] = payload
        return Page(*b.request(page.action, form))

    # happy path
    b, page = open_login()
    c.check("login page carries a challenge", page.status == 200 and page.challenge, describe(page))
    params = json.loads(page.challenge)["parameters"]
    c.check("challenge uses the default difficulty", params["keyPrefix"] == "0000", params)
    t = time.monotonic()
    payload = solve(page.challenge)
    print(f"     solved difficulty {len(params['keyPrefix'])} cost {params['cost']} in {time.monotonic() - t:.2f}s")
    res = post(b, page, payload=payload)
    c.check("valid payload + password -> redirect with code",
            res.code() and res.location.startswith(redirect_uri), describe(res))

    # missing / tampered payload
    b, page = open_login()
    res = post(b, page)
    c.check("missing payload -> altchaFailed", is_altcha_failure(res), describe(res))
    c.check("failure page issues a fresh challenge", res.challenge and res.challenge != page.challenge)
    res2 = post(b, res, payload=tamper(solve(res.challenge)))
    c.check("tampered payload -> altchaFailed", is_altcha_failure(res2), describe(res2))

    # wrong password with a valid captcha, then replay of the same payload
    b, page = open_login()
    payload = solve(page.challenge)
    res = post(b, page, password="wrong", payload=payload)
    c.check("wrong password + valid payload -> invalid credentials (not altchaFailed)",
            is_invalid_credentials(res), describe(res))
    charged = failures()
    c.check("brute-force detection counted the wrong password", charged >= 1, charged)
    # every failure page issues a new nonce, so this shows nonce binding; the parallel check
    # below covers single use
    res = post(b, res, payload=payload)
    c.check("replayed payload after a submit -> altchaFailed", is_altcha_failure(res), describe(res))
    for _ in range(3):  # the session now has tester as attempted username
        res = post(b, res, password="wrong", payload="garbage")
    c.check("login: captcha failures are not charged as failed logins",
            is_altcha_failure(res) and failures() == charged, f"{charged} -> {failures()}")

    # one solution submitted in parallel: exactly one request may get past the captcha. A race is
    # not deterministic, so several rounds (without the fix most rounds let 2-5 of 5 through).
    through = []
    for _ in range(5):
        b, page = open_login()
        payload = solve(page.challenge)
        barrier, results = threading.Barrier(5), []

        def racer():
            barrier.wait()
            results.append(post(b, page, password="wrong", payload=payload, username="nobody"))

        threads = [threading.Thread(target=racer) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        through.append(sum(is_invalid_credentials(r) for r in results))
    c.check("5 parallel submits of one solution -> exactly one reaches the password check (5 rounds)",
            through == [1] * 5, through)

    # payload solved on an older page of the same session
    b, page = open_login()
    old = solve(page.challenge)
    page = Page(*b.request(url))
    res = post(b, page, payload=old)
    c.check("payload from a previous page -> altchaFailed", is_altcha_failure(res), describe(res))

    events = admin("GET", f"/{realm}/events?type=LOGIN_ERROR&max=100")
    c.check("LOGIN_ERROR events carry error invalid_captcha",
            any(e.get("error") == "invalid_captcha" for e in events), events[:3])

    # authenticator config through the Admin REST API
    config_id = admin("POST", f"/{realm}/authentication/executions/{login_exec}/config",
                      {"alias": "altcha-e2e-login", "config": {"altchaEnabled": "false"}})
    b, page = open_login()
    c.check("disabled: no challenge attribute", not page.challenge, page.challenge)
    res = post(b, page)
    c.check("disabled: login without payload succeeds", res.code(), describe(res))
    admin("PUT", f"/{realm}/authentication/config/{config_id}",
          {"id": config_id, "alias": "altcha-e2e-login",
           "config": {"altchaEnabled": "true", "altchaDifficulty": "3"}})
    b, page = open_login()
    c.check("re-enabled with difficulty 3 -> keyPrefix 000",
            page.challenge and json.loads(page.challenge)["parameters"]["keyPrefix"] == "000", page.challenge)
    res = post(b, page)
    c.check("re-enabled: missing payload -> altchaFailed", is_altcha_failure(res), describe(res))
    res = post(b, res, payload=solve(res.challenge))
    c.check("re-enabled: valid payload -> code", res.code(), describe(res))

    # forgot password
    b, page = open_login()
    reset = Page(*b.request(urllib.parse.urljoin(url, page.reset_url)))
    c.check("reset page carries a challenge", reset.status == 200 and reset.challenge, describe(reset))
    res = Page(*b.request(reset.action, {"username": "tester", "altcha": tamper(solve(reset.challenge))}))
    c.check("reset: tampered payload -> altchaFailed", is_altcha_failure(res), describe(res))
    charged = failures()
    for _ in range(3):
        res = Page(*b.request(res.action, {"username": "tester", "altcha": "garbage"}))
    c.check("reset: captcha failures are not charged to the named user",
            is_altcha_failure(res) and failures() == charged, f"{charged} -> {failures()}")
    res = Page(*b.request(res.action, {"username": "tester", "altcha": solve(res.challenge)}))
    # The realm has no SMTP server. Keycloak does not reveal that (it says "you should receive an
    # email" and goes back to the login page) but records that the mail step after ours ran.
    c.check("reset: valid payload passes the captcha step",
            res.status == 200 and not is_altcha_failure(res), describe(res))
    c.check("reset: invalid_captcha recorded for the tampered attempt",
            any(e.get("error") == "invalid_captcha"
                for e in admin("GET", f"/{realm}/events?type=RESET_PASSWORD_ERROR&max=100")))
    sent = admin("GET", f"/{realm}/events?type=SEND_RESET_PASSWORD_ERROR&max=100")
    c.check("reset: mail step reached for tester (email_send_failed, no SMTP configured)",
            any(e.get("details", {}).get("username") == "tester" for e in sent), sent)

    # passkeys (conditional WebAuthn UI) post from a separate form with no ALTCHA field
    rep = admin("GET", f"/{realm}")  # a PUT with only this field is ignored
    rep["webAuthnPolicyPasswordlessPasskeysEnabled"] = True
    admin("PUT", f"/{realm}", rep)
    c.check("passkeys enabled on the realm",
            admin("GET", f"/{realm}").get("webAuthnPolicyPasswordlessPasskeysEnabled") is True)
    b, page = open_login()
    # what the hidden passkey form posts when the user cancels the browser's passkey prompt
    res = Page(*b.request(page.action, {"clientDataJSON": "", "authenticatorData": "", "signature": "",
                                        "credentialId": "", "userHandle": "", "error": "NotAllowedError"}))
    c.check("passkey post -> handled by the passkey step, not altchaFailed",
            res.status == 200 and "Passkey" in res.message and not is_altcha_failure(res), describe(res))
    c.check("passkey error page carries a fresh challenge",
            res.challenge and res.challenge != page.challenge, res.challenge)


def run_smoke(args):
    base = args.base_url.rstrip("/")
    c = Checks()
    b = Browser(args.insecure)
    page = Page(*b.request(auth_url(base, args.realm, args.client_id, args.redirect_uri)))
    c.check("login page carries a challenge", page.status == 200 and page.challenge, describe(page))
    if not page.challenge:
        return c.summary()
    params = json.loads(page.challenge)["parameters"]
    t = time.monotonic()
    payload = solve(page.challenge)
    print(f"     solved difficulty {len(params['keyPrefix'])} cost {params['cost']} in {time.monotonic() - t:.2f}s")
    if args.username:
        res = Page(*b.request(page.action, {"username": args.username, "password": args.password,
                                            "altcha": payload}))
        c.check("valid payload + credentials -> redirect with code", res.code(), describe(res))
    else:
        # a made-up user: the captcha must pass and only the credentials be rejected
        res = Page(*b.request(page.action, {"username": "altcha-smoke-" + secrets.token_hex(4),
                                            "password": secrets.token_hex(8), "altcha": payload}))
        c.check("valid payload passes the captcha (rejected as invalid credentials)",
                not is_altcha_failure(res) and res.status == 200 and res.message, describe(res))
        res = Page(*b.request(res.action, {"username": "x", "password": "x", "altcha": payload}))
        c.check("replayed payload -> altchaFailed", is_altcha_failure(res), describe(res))
    return c.summary()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    for mode in ("full", "smoke"):
        p = sub.add_parser(mode)
        p.add_argument("--base-url", required=True, help="Keycloak root, e.g. http://127.0.0.1:8080")
        p.add_argument("--resolve", action="append", metavar="HOST:PORT:IP",
                       help="connect to IP for HOST:PORT (Host header and TLS SNI unchanged)")
        p.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
        if mode == "full":
            p.add_argument("--admin-user", required=True)
            p.add_argument("--admin-password", required=True)
            p.add_argument("--realm", default="altcha-e2e", help="created by the test; must not exist")
            p.add_argument("--login-theme", default="altcha-e2e")
            p.add_argument("--keep", action="store_true", help="keep the realm afterwards")
        else:
            p.add_argument("--realm", required=True)
            p.add_argument("--client-id", default="account-console")
            p.add_argument("--redirect-uri", required=True)
            p.add_argument("--username")
            p.add_argument("--password")
    args = ap.parse_args()
    install_resolve(args.resolve)
    sys.exit(run_full(args) if args.mode == "full" else run_smoke(args))


if __name__ == "__main__":
    main()
