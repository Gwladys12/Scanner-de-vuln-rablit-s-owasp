#!/usr/bin/env python3
"""
full_owasp_tester.py
Usage:
  python full_owasp_tester.py <START_URL> [--max-pages N] [--output out.json] [--html-report out.html]
      [--delay 0.5] [--selenium] [--active-csrf] [--broken-auth] [--idor]
      [--http-auth user:pass] [--login user:pass] [--weak-creds creds.txt]

NE LANCE CE SCRIPT QUE SUR DES CIBLES AUTORISÉES.
"""

import argparse
import json
import socket
import time
import re
import os
from collections import deque
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup
from requests.utils import dict_from_cookiejar

# optional
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False

# HTML templating
try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except Exception:
    JINJA_AVAILABLE = False

# -------------------------
# Default config & payloads
# -------------------------
USER_AGENT = "Mozilla/5.0 (compatible; OWASPTester/1.0; +https://example.com)"
REQUEST_TIMEOUT = 10

SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR '1'='1' -- "]
XSS_PAYLOADS = ["<img src=x onerror=console.log('__XSS__')>", "\"'><script>console.log('__XSS__')</script>"]
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlite3\.OperationalError",
    r"PG::SyntaxError",
    r"mysql_fetch_array\(",
    r"ORA-\d+",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)
SECURITY_HEADERS = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"]

# -------------------------
# Helpers
# -------------------------
def check_domain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def is_html_response(resp):
    if resp is None:
        return False
    content_type = resp.headers.get("Content-Type", "")
    return "html" in content_type.lower()

def render_with_selenium(url, wait_seconds=1.0):
    if not SELENIUM_AVAILABLE:
        return None, "selenium_not_available"
    driver = None
    try:
        options = ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--log-level=3")
        service = ChromeService(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(20)
        driver.get(url)
        time.sleep(wait_seconds)
        html = driver.page_source
        driver.quit()
        return html, None
    except Exception as e:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass
        return None, str(e)

# -------------------------
# Form & link extraction
# -------------------------
def extract_forms(soup, base_url):
    forms = []
    for form in soup.find_all("form"):
        f = {"action": urljoin(base_url, form.get("action", "")),
             "method": form.get("method", "get").lower(),
             "inputs": []}
        for inp in form.find_all("input"):
            f["inputs"].append({"type": inp.get("type", "text").lower(),
                                "name": inp.get("name"),
                                "value": inp.get("value", "")})
        for ta in form.find_all("textarea"):
            f["inputs"].append({"type": "textarea", "name": ta.get("name"), "value": ta.text or ""})
        for sel in form.find_all("select"):
            options = [opt.get("value") for opt in sel.find_all("option")]
            f["inputs"].append({"type": "select", "name": sel.get("name"), "options": options})
        forms.append(f)
    return forms

def get_links_from_soup(soup, base_url, domain):
    links = set()
    for a in soup.find_all("a", href=True):
        absolute = urljoin(base_url, a.get("href"))
        parsed = urlparse(absolute)
        if parsed.netloc == domain and absolute.startswith(("http://", "https://")):
            absolute = absolute.split('#')[0]
            links.add(absolute)
    return list(links)

# -------------------------
# Passive checks
# -------------------------
def passive_csrf_check(form):
    token_names = ["csrf", "csrf_token", "token", "_csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"]
    for inp in form["inputs"]:
        name = (inp.get("name") or "").lower()
        typ = inp.get("type")
        if typ == "hidden" and any(t in name for t in token_names):
            return True, name
    return False, None

def login_form_weakness_checks(form):
    has_password = any(inp.get("type") == "password" for inp in form["inputs"])
    issues = []
    # method get + password field is weak
    if has_password:
        if form.get("method","get").lower() == "get":
            issues.append("login_using_get")
        token_present, token_name = passive_csrf_check(form)
        if not token_present:
            issues.append("login_no_csrf_token")
        # find password constraints
        for inp in form["inputs"]:
            if inp.get("type") == "password":
                # we can't access minlength from parsed bs4 easily unless attribute exists: but value present as 'minlength'
                # we'll mark if no minlength attribute in original input tag - but we didn't store attributes
                # so advise: this check is best-effort: if value was present in 'value' field and small -> warn
                pass
    return has_password, issues

def security_headers_check(resp):
    missing = []
    headers = {k.lower(): v for k, v in resp.headers.items()} if resp is not None else {}
    for h in SECURITY_HEADERS:
        if h not in headers:
            missing.append(h)
    return missing

# -------------------------
# Submit helpers
# -------------------------
def prepare_data_for_form(form, payload):
    data = {}
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name:
            continue
        typ = inp.get("type", "text")
        if typ in ("submit","button","image","file"):
            data[name] = inp.get("value", "")
            continue
        if typ == "select":
            options = inp.get("options") or []
            data[name] = options[0] if options else payload
            continue
        data[name] = payload
    return data

def submit_form(session, form, payload, method_override=None):
    method = method_override or form.get("method","get").lower()
    action = form.get("action") or session.headers.get("Referer") or ""
    data = prepare_data_for_form(form, payload)
    if not data:
        return None, "no_named_fields"
    try:
        if method == "get":
            parsed = urlparse(action)
            existing_qs = parse_qs(parsed.query)
            merged = {**{k:v[0] for k,v in existing_qs.items()}, **data}
            new_qs = urlencode(merged, doseq=False)
            new_parsed = parsed._replace(query=new_qs)
            target = urlunparse(new_parsed)
            resp = session.get(target, timeout=REQUEST_TIMEOUT)
        else:
            target = action
            resp = session.post(target, data=data, timeout=REQUEST_TIMEOUT)
        return resp, None
    except Exception as e:
        return None, str(e)

def analyze_basic_injection(resp, payload):
    evidence = {"status_code": None, "response_length": None, "sql_error": False, "sql_error_match": None, "payload_reflected": False}
    if resp is None:
        return evidence
    evidence["status_code"] = resp.status_code
    text = resp.text or ""
    evidence["response_length"] = len(text)
    m = SQL_ERROR_RE.search(text)
    if m:
        evidence["sql_error"] = True
        evidence["sql_error_match"] = m.group(0)
    if payload in text:
        evidence["payload_reflected"] = True
    return evidence

# -------------------------
# OWASP extra tests (active but safe heuristics)
# -------------------------
def active_csrf_test(session, form):
    """
    Soumet le formulaire en enlevant les champs 'hidden' suspects de token.
    Si la soumission aboutit (200 ou redirection sans erreur) -> possible absence d'enforcement.
    """
    # build data without hidden token-like fields
    token_names = ["csrf", "csrf_token", "token", "_csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"]
    data = {}
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name:
            continue
        typ = inp.get("type")
        if typ == "hidden" and any(t in (name or "").lower() for t in token_names):
            # skip token field (simulate missing token)
            continue
        # otherwise put a benign value
        if typ in ("submit","button","file","image"):
            data[name] = inp.get("value","")
        elif typ == "select":
            opts = inp.get("options") or []
            data[name] = opts[0] if opts else "1"
        else:
            data[name] = "test"
    if not data:
        return {"tested": False, "reason": "no_testable_fields"}
    try:
        method = form.get("method","get").lower()
        action = form.get("action") or session.headers.get("Referer") or ""
        if method == "get":
            parsed = urlparse(action)
            existing_qs = parse_qs(parsed.query)
            merged = {**{k:v[0] for k,v in existing_qs.items()}, **data}
            new_qs = urlencode(merged, doseq=False)
            new_parsed = parsed._replace(query=new_qs)
            target = urlunparse(new_parsed)
            resp = session.get(target, timeout=REQUEST_TIMEOUT)
        else:
            target = action
            resp = session.post(target, data=data, timeout=REQUEST_TIMEOUT)
        return {"tested": True, "status": resp.status_code, "resp_len": len(resp.text), "url": getattr(resp, "url", action)}
    except Exception as e:
        return {"tested": True, "error": str(e)}

def broken_auth_tests(session, form, weak_creds_list=None, auto_login=False):
    """
    Tests sur formulaires de login :
    - passive checks performed earlier (method GET, no CSRF token)
    - optionally try weak credentials (if provided) and record responses
    """
    results = {"passive": {}, "active_attempts": []}
    token_present, token_name = passive_csrf_check(form)
    results["passive"]["csrf_present"] = token_present
    if form.get("method","get").lower() == "get" and any(inp.get("type") == "password" for inp in form["inputs"]):
        results["passive"]["login_uses_get"] = True
    else:
        results["passive"]["login_uses_get"] = False

    if weak_creds_list:
        for cred in weak_creds_list:
            user, pwd = cred.strip().split(":",1) if ":" in cred else (cred.strip(), "password")
            # build payload per form
            data = {}
            for inp in form["inputs"]:
                n = inp.get("name")
                if not n:
                    continue
                t = inp.get("type")
                if t == "password":
                    data[n] = pwd
                elif t in ("text","email","search"):
                    data[n] = user
                elif t in ("submit","button","image"):
                    data[n] = inp.get("value","")
                else:
                    data[n] = "test"
            # attempt submit
            try:
                if form.get("method","get").lower() == "get":
                    parsed = urlparse(form.get("action") or "")
                    existing_qs = parse_qs(parsed.query)
                    merged = {**{k:v[0] for k,v in existing_qs.items()}, **data}
                    new_qs = urlencode(merged, doseq=False)
                    new_parsed = parsed._replace(query=new_qs)
                    target = urlunparse(new_parsed)
                    resp = session.get(target, timeout=REQUEST_TIMEOUT)
                else:
                    target = form.get("action") or ""
                    resp = session.post(target, data=data, timeout=REQUEST_TIMEOUT)
                results["active_attempts"].append({"cred": f"{user}:{pwd}", "status": resp.status_code, "len": len(resp.text)})
            except Exception as e:
                results["active_attempts"].append({"cred": f"{user}:{pwd}", "error": str(e)})
    return results

def idor_test(session, url):
    """
    Simple heuristic: if url path contains numeric segment, attempt +/-1 variations.
    Compare status code and response length differences.
    """
    parsed = urlparse(url)
    parts = parsed.path.rstrip("/").split("/")
    numeric_indexes = []
    for idx, p in enumerate(parts):
        if p.isdigit():
            numeric_indexes.append(idx)
    findings = []
    for idx in numeric_indexes:
        orig = int(parts[idx])
        for delta in (-1,1):
            parts2 = list(parts)
            parts2[idx] = str(orig + delta)
            new_path = "/".join(parts2)
            new_parsed = parsed._replace(path=new_path)
            new_url = urlunparse(new_parsed)
            try:
                resp = session.get(new_url, timeout=REQUEST_TIMEOUT)
                findings.append({"tested_url": new_url, "status": resp.status_code, "len": len(resp.text)})
            except Exception as e:
                findings.append({"tested_url": new_url, "error": str(e)})
    return findings

# -------------------------
# Crawl + orchestration
# -------------------------
def crawl_and_test(start_url, max_pages=20, delay=0.5, use_selenium=False, enable_active_csrf=False,
                   enable_broken_auth=False, enable_idor=False, http_auth=None, login_cred=None, weak_creds=None):
    parsed_start = urlparse(start_url)
    domain = parsed_start.netloc
    if not check_domain(domain):
        print(f"[!] Domaine introuvable: {domain}")
        return []

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Referer": start_url})
    if http_auth:
        try:
            user, pwd = http_auth.split(":",1)
            session.auth = (user, pwd)
        except Exception:
            print("[!] http-auth format should be user:pass")

    # If login_cred provided, attempt to find a login form on start_url and submit before crawling
    if login_cred:
        user, pwd = login_cred.split(":",1)
        try:
            resp0 = session.get(start_url, timeout=REQUEST_TIMEOUT)
            if is_html_response(resp0):
                soup0 = BeautifulSoup(resp0.text, "html.parser")
                forms0 = extract_forms(soup0, start_url)
                # naive: choose first form with a password field
                login_form = None
                for f in forms0:
                    if any(inp.get("type")=="password" for inp in f["inputs"]):
                        login_form = f
                        break
                if login_form:
                    data = {}
                    for inp in login_form["inputs"]:
                        n = inp.get("name")
                        if not n:
                            continue
                        t = inp.get("type")
                        if t == "password":
                            data[n] = pwd
                        elif t in ("text","email","search"):
                            data[n] = user
                        else:
                            data[n] = inp.get("value","")
                    try:
                        if login_form.get("method")=="get":
                            parsed = urlparse(login_form.get("action") or start_url)
                            existing_qs = parse_qs(parsed.query)
                            merged = {**{k:v[0] for k,v in existing_qs.items()}, **data}
                            q = urlencode(merged, doseq=False)
                            newp = parsed._replace(query=q)
                            target = urlunparse(newp)
                            rlogin = session.get(target, timeout=REQUEST_TIMEOUT)
                        else:
                            target = login_form.get("action") or start_url
                            rlogin = session.post(target, data=data, timeout=REQUEST_TIMEOUT)
                        print(f"[+] Tentative de login faite, status: {getattr(rlogin,'status_code',None)}")
                    except Exception as e:
                        print("[!] Erreur lors de la soumission du formulaire de login:", e)
                else:
                    print("[!] Aucun formulaire de login trouvé pour la soumission automatique.")
        except Exception as e:
            print("[!] Erreur initiale lors de récupération de la page start pour login:", e)

    visited = set()
    queue = deque([start_url])
    report = []
    baseline_map = {}

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        print(f"\n[*] Visiting: {url}")
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            print("  Request error:", e)
            continue
        time.sleep(delay)
        baseline_map[url] = len(resp.text) if resp is not None else 0

        page = {"page_url": url,
                "status": resp.status_code if resp is not None else None,
                "headers": dict(resp.headers) if resp is not None else {},
                "missing_security_headers": security_headers_check(resp),
                "cookies": dict_from_cookiejar(resp.cookies) if resp is not None else {},
                "forms": [],
                "idor_findings": []}

        if not is_html_response(resp):
            print("  Non-HTML -> skip forms")
        else:
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = extract_forms(soup, url)
            links = get_links_from_soup(soup, url, domain)

            if use_selenium:
                rendered_html, err = render_with_selenium(url)
                if rendered_html:
                    soup_r = BeautifulSoup(rendered_html, "html.parser")
                    forms_r = extract_forms(soup_r, url)
                    if forms_r:
                        print(f"  Selenium added {len(forms_r)} forms")
                        forms += forms_r

            # process each form
            for i, form in enumerate(forms, start=1):
                frec = {"form_index": i, "action": form.get("action"), "method": form.get("method"),
                        "inputs": form.get("inputs"), "passive": {}, "tests": []}

                # passive checks
                token_present, token_name = passive_csrf_check(form)
                frec["passive"]["csrf_present"] = token_present
                frec["passive"]["csrf_token_name"] = token_name
                has_pw, login_issues = login_form_weakness_checks(form)
                frec["passive"]["has_password_field"] = has_pw
                frec["passive"]["login_issues"] = login_issues

                # Basic active tests: SQLi & XSS (non-destructive)
                for payload in SQLI_PAYLOADS:
                    resp_p, err = submit_form(session, form, payload)
                    if err:
                        frec["tests"].append({"type":"sqli", "payload":payload, "tested":False, "reason":err})
                    else:
                        evidence = analyze_basic_injection(resp_p, payload)
                        evidence["baseline_len"] = baseline_map.get(url)
                        evidence["len_diff"] = evidence["response_length"] - baseline_map.get(url,0) if evidence["response_length"] is not None else None
                        frec["tests"].append({"type":"sqli", "payload":payload, "tested":True, "evidence":evidence})
                    time.sleep(delay)

                for payload in XSS_PAYLOADS:
                    resp_p, err = submit_form(session, form, payload)
                    if err:
                        frec["tests"].append({"type":"xss","payload":payload,"tested":False,"reason":err})
                    else:
                        evidence = analyze_basic_injection(resp_p, payload)
                        frec["tests"].append({"type":"xss","payload":payload,"tested":True,"evidence":evidence})
                    time.sleep(delay)

                # Active CSRF enforcement test (only if enabled)
                if enable_active_csrf:
                    cs = active_csrf_test(session, form)
                    frec["tests"].append({"type":"active_csrf", "result": cs})

                # Broken auth tests (if enabled and form looks like login)
                if enable_broken_auth and has_pw:
                    bat = broken_auth_tests(session, form, weak_creds_list=weak_creds)
                    frec["tests"].append({"type":"broken_auth", "result": bat})

                page["forms"].append(frec)

            # IDOR tests on page itself (if enabled)
            if enable_idor:
                idor = idor_test(session, url)
                page["idor_findings"] = idor

            # enqueue links
            for l in links:
                if l not in visited and l not in queue and len(visited) + len(queue) < max_pages:
                    queue.append(l)

        report.append(page)

    return report

# -------------------------
# HTML report generator
# -------------------------
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>OWASP Test Report</title>
<style>
body{font-family:Inter,Segoe UI,Arial,Helvetica,sans-serif;background:#f5f7fb;color:#111;padding:20px}
.container{max-width:1100px;margin:0 auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,0.06)}
h1{margin-top:0}
.summary{display:flex;gap:12px;flex-wrap:wrap}
.card{background:#f8fafc;border:1px solid #e6eef6;padding:12px;border-radius:8px;min-width:200px}
.high{color:#7d0202;font-weight:600}
.medium{color:#7d5a02}
.low{color:#045604}
.page{border-top:1px solid #eee;padding-top:12px;margin-top:12px}
.form-block{background:#fafafa;border:1px solid #eee;padding:10px;margin:10px 0;border-radius:6px}
pre{white-space:pre-wrap;background:#0b1220;color:#cfe8ff;padding:10px;border-radius:6px}
</style>
</head>
<body>
<div class="container">
  <h1>OWASP Test Report</h1>
  <p>Start URL: {{ start_url }} — Pages scanned: {{ pages_count }}</p>
  <div class="summary">
    <div class="card"><strong>High</strong><div>{{counts.high}}</div></div>
    <div class="card"><strong>Medium</strong><div>{{counts.medium}}</div></div>
    <div class="card"><strong>Low</strong><div>{{counts.low}}</div></div>
  </div>

  {% for page in report %}
  <div class="page">
    <h2>Page: {{ page.page_url }}</h2>
    <div>Status: {{page.status}}</div>
    <div>Missing security headers: {{page.missing_security_headers}}</div>
    <div>Cookies: {{page.cookies|length}}</div>

    {% if page.forms %}
      <h3>Forms ({{page.forms|length}})</h3>
      {% for f in page.forms %}
        <div class="form-block">
          <div><strong>Form #{{f.form_index}}</strong> — method: {{f.method}} action: {{f.action}}</div>
          <div>Passive: csrf_present={{f.passive.csrf_present}} login_issues={{f.passive.login_issues}}</div>
          <h4>Tests:</h4>
          <ul>
          {% for t in f.tests %}
            <li>
              <strong>{{t.type}}</strong>
              {% if t.tested is defined and t.tested %}
                {% if t.evidence %}
                  {% if t.evidence.sql_error %}
                    <span class="high"> SQL Error detected </span>
                  {% endif %}
                  {% if t.evidence.payload_reflected %}
                    <span class="medium"> Payload reflected </span>
                  {% endif %}
                {% endif %}
              {% elif t.result is defined %}
                <pre>{{t.result}}</pre>
              {% else %}
                <span class="low">not tested / error</span>
              {% endif %}
            </li>
          {% endfor %}
          </ul>
        </div>
      {% endfor %}
    {% endif %}

    {% if page.idor_findings %}
      <h3>IDOR tests</h3>
      <pre>{{page.idor_findings}}</pre>
    {% endif %}
  </div>
  {% endfor %}
</div>
</body>
</html>
"""

def generate_html_report(report, start_url, out_html):
    if not JINJA_AVAILABLE:
        # fallback: very simple html
        try:
            with open(out_html, "w", encoding="utf-8") as f:
                f.write("<html><body><pre>")
                f.write(json.dumps(report, ensure_ascii=False, indent=2))
                f.write("</pre></body></html>")
            return True
        except Exception:
            return False
    # compute counts heuristically
    counts = {"high":0, "medium":0, "low":0}
    for page in report:
        for f in page.get("forms", []):
            for t in f.get("tests", []):
                # heuristics: sql_error -> high ; payload_reflected -> medium ; missing security headers -> low
                if t.get("tested") and t.get("evidence"):
                    ev = t.get("evidence")
                    if ev.get("sql_error"):
                        counts["high"] += 1
                    elif ev.get("payload_reflected"):
                        counts["medium"] += 1
                if f.get("passive", {}).get("csrf_present") is False:
                    counts["low"] += 0  # passive info
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(report=report, start_url=start_url, pages_count=len(report), counts=counts)
    try:
        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html)
        return True
    except Exception:
        return False

# -------------------------
# CLI Entrypoint
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Advanced OWASP-lite form tester (educational).")
    parser.add_argument("start_url", help="Start URL (include scheme, e.g. https://example.com)")
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--output", default="owasp_report.json", help="JSON output filename")
    parser.add_argument("--html-report", default=None, help="Optional HTML output filename")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    parser.add_argument("--selenium", action="store_true", help="Use Selenium to render pages (requires selenium & webdriver-manager)")
    parser.add_argument("--active-csrf", action="store_true", help="Perform active CSRF enforcement tests (use with caution)")
    parser.add_argument("--broken-auth", action="store_true", help="Perform broken-auth tests (passive + optional active weak creds)")
    parser.add_argument("--idor", action="store_true", help="Perform basic IDOR heuristics")
    parser.add_argument("--http-auth", help="HTTP Basic auth (user:pass)")
    parser.add_argument("--login", help="Form-based login auto attempt (user:pass)")
    parser.add_argument("--weak-creds", help="File with weak creds (user:pass) one per line for testing broken-auth")
    args = parser.parse_args()

    print("\n*** AVERTISSEMENT: N'UTILISEZ QUE SUR CIBLES AUTORISÉES ***\n")
    if args.selenium and not SELENIUM_AVAILABLE:
        print("[!] Selenium non disponible — installez selenium & webdriver-manager")
        return
    if args.html_report and not JINJA_AVAILABLE:
        print("[!] jinja2 non installé, HTML report sera basique. Pour améliorer installer jinja2 (pip install jinja2)")

    weak_creds = None
    if args.weak_creds:
        if os.path.exists(args.weak_creds):
            with open(args.weak_creds, "r", encoding="utf-8") as f:
                weak_creds = [l.strip() for l in f if l.strip()]
        else:
            print("[!] weak-creds file not found, skipping active weak-creds tests.")
            weak_creds = None

    report = crawl_and_test(args.start_url,
                            max_pages=args.max_pages,
                            delay=args.delay,
                            use_selenium=args.selenium,
                            enable_active_csrf=args.active_csrf,
                            enable_broken_auth=args.broken_auth,
                            enable_idor=args.idor,
                            http_auth=args.http_auth,
                            login_cred=args.login,
                            weak_creds=weak_creds)

    # write JSON
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[+] JSON report saved to: {args.output}")
    except Exception as e:
        print("[!] Unable to write JSON:", e)

    # HTML
    if args.html_report:
        ok = generate_html_report(report, args.start_url, args.html_report)
        if ok:
            print(f"[+] HTML report saved to: {args.html_report}")
        else:
            print("[!] Failed to create HTML report")

if __name__ == "__main__":
    main()
