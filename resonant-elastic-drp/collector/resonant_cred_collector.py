#!/usr/bin/env python3
"""resonant_cred_collector.py - coletor de credenciais vazadas (Tempest Resonant DRP).

Pagina /leaked_credentials ATE o total, redige segredos (signal-only) e escreve NDJSON
no spool para o Logstash (file input).

NOVIDADE: enriquece cada credencial com o FINDING (a "Ameaca" DRP-xxx da plataforma).
Antes de coletar as credenciais, busca /findings/search (sao poucas dezenas), monta um
mapa finding_uuid -> {key, published_at, title, status, priority, type} em memoria e
carimba cada credencial. Assim o indice ganha resonant.finding.key (DRP-xxx) etc. sem
precisar de dicionario/translate/cron extra.

Segredo NUNCA vai a disco/indice: password/CPF/CNPJ viram has_*/length. Fingerprint
(event.hash) usa sha256 LOCAL da senha, nunca persistido. Idempotente (document_id=hash).
Python 3.6+, curl. Somente leitura.

Uso:
  RESONANT_TOKEN_FILE=/caminho/token QUERY='brand:MINHAMARCA' \
    SPOOL=/caminho/spool python3 resonant_cred_collector.py
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

API = "https://api.tempest.center/rest/monitoring/v2"
CACERT = os.environ.get("CACERT", "/etc/pki/tls/certs/ca-bundle.crt")
QUERY = os.environ.get("QUERY", "").strip()
SPOOL = os.environ.get("SPOOL", "/var/spool/resonant")
MAX_PAGES = int(os.environ.get("MAX_PAGES", "1000"))
PAGE_MAX_TIME = int(os.environ.get("PAGE_MAX_TIME", "600"))
TZ = timezone(timedelta(hours=-3))
SECRET_SMELL = re.compile(r"(pass|senha|pwd|secret|token|hash|cookie|cvv|card)", re.I)


def load_token():
    tok = os.environ.get("RESONANT_TOKEN", "").strip()
    if not tok and os.environ.get("RESONANT_TOKEN_FILE"):
        p = os.environ["RESONANT_TOKEN_FILE"]
        if os.stat(p).st_mode & 0o077:
            sys.exit("Token file com permissao aberta; chmod 600 " + p)
        tok = open(p, encoding="utf-8").read().strip()
    if tok.lower().startswith("bearer "):
        tok = tok[7:].strip()
    if not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", tok or ""):
        sys.exit("Token ausente/invalido (RESONANT_TOKEN ou RESONANT_TOKEN_FILE).")
    return tok


def curl(token, method, path, query=None, body=None):
    url = API + path + ("?" + urlencode(query) if query else "")
    with tempfile.TemporaryDirectory(prefix="resonant_") as tmp:
        bp, hp = os.path.join(tmp, "b"), os.path.join(tmp, "h")
        cmd = ["curl", "-q", "-sS", "--proto", "=https", "--cacert", CACERT,
               "--connect-timeout", "15", "--max-time", str(PAGE_MAX_TIME), "-K", "-", url,
               "-X", method, "-H", "Accept: application/json", "-D", hp, "-o", bp, "-w", "%{http_code}"]
        if body is not None:
            cmd += ["-H", "Content-Type: application/json", "--data", json.dumps(body)]
        cfg = 'header = "Authorization: Bearer ' + token + '"\n'
        proc = subprocess.run(cmd, input=cfg, universal_newlines=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=PAGE_MAX_TIME + 30)
        code = int(proc.stdout.strip()) if proc.stdout.strip().isdigit() else 0
        hdr = open(hp, errors="replace").read() if os.path.exists(hp) else ""
        raw = open(bp, encoding="utf-8", errors="replace").read() if os.path.exists(bp) else ""
    m = re.search(r"(?im)^retry-after:\s*(\d+)", hdr)
    return code, raw, (int(m.group(1)) if m else None)


def values_of(body):
    if isinstance(body, dict):
        return body.get("values") or []
    if isinstance(body, list):
        out = []
        for e in body:
            if isinstance(e, dict):
                out.extend(e.get("values") or [])
        return out
    return []


def build_findings_map(token):
    """finding_uuid -> {key, published_at, title, status, priority, type}. Poucos findings."""
    fmap, total = {}, None
    for page in range(1, 200):
        code, raw, _ = curl(token, "POST", "/findings/search", body={
            "page": page, "limit": 100, "order": {"published_at": -1}})
        if code == 404:
            break
        if code != 200:
            sys.stderr.write("findings/search pagina {}: HTTP {} (segue sem ameaca)\n".format(page, code))
            break
        try:
            vals = values_of(json.loads(raw))
        except ValueError:
            break
        if not vals:
            break
        for f in vals:
            u = f.get("uuid")
            if not u:
                continue
            fmap[u] = {k: f.get(k) for k in ("key", "published_at", "title", "status",
                                             "priority", "type") if f.get(k) not in (None, "")}
        if len(vals) < 100:
            break
        time.sleep(0.2)
    sys.stderr.write("findings mapeados: {}\n".format(len(fmap)))
    return fmap


def s(v):
    return v if isinstance(v, str) else ""


def normalize(c, fmap):
    if not isinstance(c, dict):
        return None
    email = s(c.get("email")).strip()
    uname = s(c.get("username")).strip()
    url = s(c.get("url")).strip()
    source = s(c.get("source")).strip()
    fuuid = s(c.get("finding_uuid")).strip()

    pw = c.get("password")
    has_pw = isinstance(pw, str) and pw != ""
    pw_token = hashlib.sha256(pw.encode("utf-8")).hexdigest() if has_pw else ""
    cred_fp = hashlib.sha256("|".join(
        [source, email.lower(), uname, url, fuuid, pw_token]).encode("utf-8")).hexdigest()

    known = ("email", "username", "url", "source", "finding_uuid", "brand", "created_at",
             "breach_date", "infection_date", "internal", "ip", "user_agent", "hostname",
             "hardware_id", "stealer_family", "malware_installation_path", "address",
             "password", "cpf", "cnpj")
    dropped = sorted(k for k in c if k not in known and SECRET_SMELL.search(k))

    # enriquecimento do finding (a "Ameaca")
    finding = {"uuid": fuuid or None}
    fmeta = fmap.get(fuuid) or {}
    if fmeta.get("key"):
        finding["key"] = fmeta["key"]                 # DRP-xxx
    if fmeta.get("title"):
        finding["title"] = fmeta["title"]
    if fmeta.get("status") is not None:
        finding["status"] = fmeta["status"]
    if fmeta.get("priority") is not None:
        finding["priority"] = fmeta["priority"]
    if fmeta.get("type") is not None:
        finding["type"] = fmeta["type"]
    if fmeta.get("published_at"):
        finding["published_at"] = fmeta["published_at"]

    doc = {
        "event": {"kind": "event", "category": ["threat"], "type": ["indicator"],
                  "dataset": "resonant_credentials_exposure", "provider": "tempest_resonant",
                  "hash": cred_fp},
        "threat": {"indicator": {"type": "credential"}},
        "resonant": {
            "brand": c.get("brand"),
            "source": source or None,
            "finding": finding,
            "breach_date": c.get("breach_date") or None,
            "infection_date": c.get("infection_date") or None,
            "exposure_scope": c.get("internal") or None,
            "stealer_family": c.get("stealer_family") or None,
            "malware_path": c.get("malware_installation_path") or None,
        },
        "credential": {
            "has_password": has_pw,
            "password_length": len(pw) if has_pw else None,
            "created_at": c.get("created_at") or None,
            "finding_uuid": fuuid or None,
        },
    }
    for k in ("cpf", "cnpj"):
        if s(c.get(k)).strip():
            doc["credential"].setdefault("national_id", {})["has_" + k] = True
    if email and "@" in email:
        local, dom = email.lower().split("@", 1)
        doc["user"] = {"email": email.lower(), "name": (uname.lower() or local), "domain": dom}
    elif uname:
        doc["user"] = {"name": uname.lower()}
    if url:
        doc["url"] = {"original": url}
    if s(c.get("ip")).strip():
        doc["related"] = {"ip": [c["ip"]]}
        doc["source"] = {"ip": c["ip"]}
    if s(c.get("user_agent")).strip():
        doc["user_agent"] = {"original": c["user_agent"]}
    if s(c.get("hostname")).strip():
        doc["credential"]["hostname"] = c["hostname"]
    if s(c.get("hardware_id")).strip():
        doc["credential"]["hardware_id"] = c["hardware_id"]
    if dropped:
        doc["resonant"]["dropped_secret_like_keys"] = dropped
    return doc


def main():
    os.umask(0o027)
    if not shutil.which("curl"):
        sys.exit("curl nao encontrado.")
    token = load_token()

    fmap = build_findings_map(token)          # <-- busca as ameacas antes das credenciais

    os.makedirs(SPOOL, exist_ok=True)
    stamp = datetime.now(TZ).strftime("%Y%m%d_%H%M%S")
    tmp_path = os.path.join(SPOOL, ".resonant_cred_{}.ndjson.part".format(stamp))
    final_path = os.path.join(SPOOL, "resonant_cred_{}.ndjson".format(stamp))

    written, seen, total = 0, set(), None
    with open(tmp_path, "w", encoding="utf-8") as fh:
        for page in range(1, MAX_PAGES + 1):
            q = {"page": page}
            if QUERY:
                q["query"] = QUERY
            t0 = time.monotonic()
            code, raw, ra = curl(token, "GET", "/leaked_credentials", query=q)
            if code == 429:
                wait = min(ra or 30, 120)
                sys.stderr.write("pagina {}: 429, aguardando {}s\n".format(page, wait))
                time.sleep(wait)
                code, raw, ra = curl(token, "GET", "/leaked_credentials", query=q)
            if code == 404:
                break
            if code != 200:
                sys.stderr.write("pagina {}: HTTP {}\n".format(page, code))
                if not written:
                    os.remove(tmp_path)
                    return 1
                break
            try:
                body = json.loads(raw)
            except ValueError:
                sys.stderr.write("pagina {}: resposta nao-JSON\n".format(page))
                break
            vals = (body.get("values") or []) if isinstance(body, dict) else []
            if isinstance(body, dict) and isinstance(body.get("total"), int):
                total = body["total"]
            new = 0
            for rec in vals:
                doc = normalize(rec, fmap)
                if doc is None:
                    continue
                fp = doc["event"]["hash"]
                if fp in seen:
                    continue
                seen.add(fp)
                fh.write(json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n")
                written += 1
                new += 1
            sys.stderr.write("pagina {}: {} recs ({} novos, acumulado {}{}) {:.1f}s\n".format(
                page, len(vals), new, written, "/" + str(total) if total is not None else "",
                time.monotonic() - t0))
            if not vals or len(vals) < 1000:
                break
            if total is not None and written >= total:
                break
            time.sleep(0.3)
    token = None

    if written == 0:
        os.remove(tmp_path)
        sys.stderr.write("Nada coletado; NDJSON nao gerado.\n")
        return 0

    os.rename(tmp_path, final_path)
    os.chmod(final_path, 0o640)
    sys.stderr.write("{}: {} credenciais (total API {}) -> {}\n".format(
        datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S"), written, total, final_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
