#!/usr/bin/env python3
"""resonant_threat_collector.py - coletor de Ameacas DRP (findings) da Tempest Resonant.

Integracao APARTADA da de credenciais vazadas (resonant_cred_collector.py):
  - spool proprio, pipeline Logstash proprio, data stream proprio
    (logs-resonant_drp_threat-resonant), cron proprio. Compartilha so token e CA.

Modelo de dados: findings sao MUTAVEIS (status/prioridade/assets mudam ao longo do
ciclo de vida: aberto -> em tratamento -> takedown -> fechado). Por isso:
  - document_id = event.hash = sha256(uuid | estado relevante)
  - op create no data stream: re-coleta sem mudanca -> 409 (dedup);
    mudanca de estado -> novo documento (historico completo do finding).
  - Estado atual = ultimo doc por uuid (INLINE STATS / transform latest).

status/priority/type sao traduzidos via /findings/statuses|priorities|types:
  resonant.finding.status (long, mesmo tipo do indice de credenciais -> sem
  conflito em FROM logs-resonant*) + resonant.finding.status_name (keyword).

Python 3.6+, curl. Somente leitura na API.

Uso:
  RESONANT_TOKEN_FILE=/caminho/token SPOOL=/caminho/spool_threat \
    [INCLUDE_TYPES='6'] [EXCLUDE_TYPES='12'] [BRAND=MINHAMARCA] \
    python3 resonant_threat_collector.py [--discover]

  --discover  imprime catalogos (status/prioridade/tipo), distribuicao por tipo e a
              estrutura de digital_assets de um finding. Nao escreve nada.
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
from collections import Counter
from datetime import datetime, timedelta, timezone

API = "https://api.tempest.center/rest/monitoring/v2"
CACERT = os.environ.get("CACERT", "/etc/pki/tls/certs/ca-bundle.crt")
SPOOL = os.environ.get("SPOOL", "/var/spool/resonant_threat")
BRAND = os.environ.get("BRAND", "").strip().lower()
EXCLUDE_TYPES = {t.strip().lower() for t in os.environ.get("EXCLUDE_TYPES", "").split(",") if t.strip()}
INCLUDE_TYPES = {t.strip().lower() for t in os.environ.get("INCLUDE_TYPES", "").split(",") if t.strip()}
PAGE_LIMIT = int(os.environ.get("PAGE_LIMIT", "100"))
MAX_PAGES = int(os.environ.get("MAX_PAGES", "1000"))
REQ_MAX_TIME = int(os.environ.get("REQ_MAX_TIME", "120"))
MAX_IOCS = int(os.environ.get("MAX_IOCS", "200"))
TZ = timezone(timedelta(hours=-3))

SECRET_SMELL = re.compile(r"(pass|senha|pwd|secret|token|cookie|cvv|card|cpf|cnpj)", re.I)
RE_URL = re.compile(r"^(?:hxxps?|https?|ftp)://", re.I)
RE_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
RE_FQDN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
# Campos do finding que definem "estado" (mudanca => novo doc). assignee fica de fora (ruido).
STATE_KEYS = ("status", "priority", "type", "title", "digital_assets", "brand", "source")


# ----------------------------------------------------------------------------- HTTP
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


def curl(token, method, path, body=None):
    """Token via stdin (-K -) -> nunca aparece em ps/argv."""
    url = API + path
    with tempfile.TemporaryDirectory(prefix="resonant_thr_") as tmp:
        bp, hp = os.path.join(tmp, "b"), os.path.join(tmp, "h")
        cmd = ["curl", "-q", "-sS", "--http1.1", "--proto", "=https", "--cacert", CACERT,
               "--connect-timeout", "15", "--max-time", str(REQ_MAX_TIME), "-K", "-", url,
               "-X", method, "-H", "Accept: application/json", "-D", hp, "-o", bp,
               "-w", "%{http_code}"]
        if body is not None:
            cmd += ["-H", "Content-Type: application/json", "--data", json.dumps(body)]
        cfg = 'header = "Authorization: Bearer ' + token + '"\n'
        proc = subprocess.run(cmd, input=cfg, universal_newlines=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=REQ_MAX_TIME + 30)
        out = proc.stdout.strip()
        code = int(out) if out.isdigit() else 0
        hdr = open(hp, errors="replace").read() if os.path.exists(hp) else ""
        raw = open(bp, encoding="utf-8", errors="replace").read() if os.path.exists(bp) else ""
    m = re.search(r"(?im)^retry-after:\s*(\d+)", hdr)
    return code, raw, (int(m.group(1)) if m else None)


def call(token, method, path, body=None):
    code, raw, ra = curl(token, method, path, body)
    if code == 429:
        wait = min(ra or 30, 120)
        sys.stderr.write("{}: 429, aguardando {}s\n".format(path, wait))
        time.sleep(wait)
        code, raw, ra = curl(token, method, path, body)
    return code, raw


def values_of(body):
    if isinstance(body, dict):
        v = body.get("values")
        return v if isinstance(v, list) else []
    if isinstance(body, list):
        out = []
        for e in body:
            if isinstance(e, dict) and isinstance(e.get("values"), list):
                out.extend(e["values"])
            elif isinstance(e, dict):
                out.append(e)
        return out
    return []


# ------------------------------------------------------------------------ catalogos
def load_catalog(token, path):
    """Formato do catalogo nao e documentado: aceita lista de dicts {id|code|value: name|label}
    ou dict {codigo: rotulo}. Falha -> {} (segue so com o codigo numerico)."""
    code, raw = call(token, "GET", path)
    if code != 200:
        sys.stderr.write("catalogo {}: HTTP {} (sem rotulo)\n".format(path, code))
        return {}
    try:
        body = json.loads(raw)
    except ValueError:
        return {}
    cat = {}
    if isinstance(body, dict) and not isinstance(body.get("values"), list):
        for k, v in body.items():
            if isinstance(v, (str, int)):
                cat[str(k)] = str(v)
        return cat
    items = values_of(body) or (body if isinstance(body, list) else [])
    for it in items:
        if not isinstance(it, dict):
            continue
        k = next((it[x] for x in ("id", "code", "value", "key") if it.get(x) is not None), None)
        n = next((it[x] for x in ("name", "label", "description", "title") if it.get(x)), None)
        if k is not None and n is not None:
            cat[str(k)] = str(n)
    return cat


# ------------------------------------------------------------------------- findings
def fetch_findings(token):
    """A API ignora o limit pedido (devolve 10/pagina). Paginacao guiada pelo 'total'
    da resposta; para em pagina vazia, 404, total atingido ou MAX_PAGES."""
    out, seen, total = [], set(), None
    for page in range(1, MAX_PAGES + 1):
        code, raw = call(token, "POST", "/findings/search", body={
            "page": page, "limit": PAGE_LIMIT, "order": {"published_at": -1}})
        if code == 404:
            break
        if code != 200:
            raise RuntimeError("findings/search pagina {}: HTTP {}".format(page, code))
        try:
            body = json.loads(raw)
        except ValueError:
            raise RuntimeError("findings/search pagina {}: resposta nao-JSON".format(page))
        head = body[0] if isinstance(body, list) and body else body
        if isinstance(head, dict) and isinstance(head.get("total"), int):
            total = head["total"]
        vals = [v for v in values_of(body) if isinstance(v, dict)]
        if not vals:
            break
        new = [v for v in vals if v.get("uuid") not in seen]
        if not new:                       # pagina repetida -> API ignorou 'page'; evita loop
            sys.stderr.write("pagina {} repetida; parando\n".format(page))
            break
        seen.update(v.get("uuid") for v in new)
        out.extend(new)
        if total is not None and len(out) >= total:
            break
        time.sleep(0.2)
    if total is not None and len(out) < total:
        sys.stderr.write("AVISO: coletados {} de {} findings (MAX_PAGES={})\n".format(
            len(out), total, MAX_PAGES))
    sys.stderr.write("findings coletados: {}/{}\n".format(len(out), total))
    return out


def scrub(obj, depth=0):
    """Remove chaves com cara de segredo (defesa em profundidade) e limita profundidade."""
    if depth > 8:
        return None
    if isinstance(obj, dict):
        return {k: scrub(v, depth + 1) for k, v in obj.items() if not SECRET_SMELL.search(str(k))}
    if isinstance(obj, list):
        return [scrub(v, depth + 1) for v in obj]
    return obj


def walk_strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_strings(v)
    elif isinstance(obj, str):
        yield obj.strip()


def refang(v):
    return re.sub(r"(?i)^hxxp", "http", v.replace("[.]", ".").replace("(.)", "."))


def extract_iocs(assets):
    urls, domains, ips = [], [], []
    for v in walk_strings(assets):
        if not v or len(v) > 2048:
            continue
        r = refang(v)
        if RE_URL.match(r):
            urls.append(r)
            host = re.sub(r"^[a-z]+://", "", r, flags=re.I).split("/")[0].split(":")[0].lower()
            (ips if RE_IPV4.match(host) else domains).append(host)
        elif RE_IPV4.match(r):
            ips.append(r)
        elif RE_FQDN.match(r):
            domains.append(r.lower().rstrip("."))
    uniq = lambda xs: list(dict.fromkeys(xs))[:MAX_IOCS]
    return uniq(urls), uniq(domains), uniq(ips)


def as_str(v):
    if v is None or v == "":
        return None
    if isinstance(v, (str, int, float)):
        return str(v)
    if isinstance(v, dict):
        for k in ("name", "email", "username", "title", "label"):
            if v.get(k):
                return str(v[k])
    return json.dumps(v, ensure_ascii=False, sort_keys=True)


def as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def type_excluded(f, cats):
    """INCLUDE_TYPES (allowlist) tem precedencia; depois EXCLUDE_TYPES. Aceita codigo ou rotulo."""
    code = f.get("type")
    keys = {str(code).lower(), cats["type"].get(str(code), "").lower()} - {""}
    if INCLUDE_TYPES and not (keys & INCLUDE_TYPES):
        return True
    return bool(keys & EXCLUDE_TYPES)


def brand_ok(f):
    if not BRAND:
        return True
    b = f.get("brand")
    vals = b if isinstance(b, list) else [b]
    return any(BRAND == (as_str(x) or "").lower() for x in vals)


def normalize(f, cats):
    uuid = as_str(f.get("uuid"))
    if not uuid:
        return None
    assets = scrub(f.get("digital_assets"))
    state = {k: (assets if k == "digital_assets" else f.get(k)) for k in STATE_KEYS}
    fp = hashlib.sha256((uuid + "|" + json.dumps(state, sort_keys=True, ensure_ascii=False,
                                                 default=str)).encode("utf-8")).hexdigest()
    urls, domains, ips = extract_iocs(assets)

    finding = {"uuid": uuid, "key": as_str(f.get("key")), "title": as_str(f.get("title")),
               "published_at": f.get("published_at") or None, "state_hash": fp}
    for fld in ("status", "priority", "type"):
        raw = f.get(fld)
        code = as_int(raw)
        finding[fld] = code
        finding[fld + "_name"] = cats[fld].get(str(raw)) or (as_str(raw) if code is None else None)
    if assets not in (None, [], {}, ""):
        # flattened exige OBJETO na raiz: a API entrega lista de strings (URLs).
        # Lista/escalar -> {"items": [...]}; dict -> como veio.
        finding["digital_assets"] = assets if isinstance(assets, dict) else {
            "items": assets if isinstance(assets, list) else [assets]}
    ind = {k: v for k, v in (("urls", urls), ("domains", domains), ("ips", ips)) if v}
    if ind:
        finding["indicators"] = ind
    finding = {k: v for k, v in finding.items() if v is not None}

    brand = f.get("brand")
    doc = {
        "event": {"kind": "event", "category": ["threat"], "type": ["indicator"],
                  "dataset": "resonant_drp_threat", "provider": "tempest_resonant",
                  "hash": fp},
        "resonant": {
            "brand": [as_str(b) for b in brand] if isinstance(brand, list) else as_str(brand),
            "source": as_str(f.get("source")),
            "assignee": as_str(f.get("assignee")),
            "finding": finding,
        },
    }
    doc["resonant"] = {k: v for k, v in doc["resonant"].items() if v not in (None, [], "")}
    rel = {}
    if domains:
        rel["hosts"] = domains
    if ips:
        rel["ip"] = ips
    if rel:
        doc["related"] = rel
    if urls:
        doc["url"] = {"original": urls[0]}
    return doc


# ----------------------------------------------------------------------------- main
def discover(token, cats, findings):
    print("== catalogos ==")
    for k in ("status", "priority", "type"):
        print("{:9} {}".format(k, json.dumps(cats[k], ensure_ascii=False)))
    print("\n== findings: {} ==".format(len(findings)))
    c = Counter((str(f.get("type")), cats["type"].get(str(f.get("type")), "?")) for f in findings)
    for (code, name), n in c.most_common():
        print("type {:>4}  {:<45} {}".format(code, name, n))
    sample = next((f for f in findings if f.get("digital_assets")), None)
    if sample:
        print("\n== digital_assets (amostra {}) ==".format(sample.get("key")))
        print(json.dumps(scrub(sample["digital_assets"]), ensure_ascii=False, indent=2)[:3000])
        print("\n== documento normalizado ==")
        print(json.dumps(normalize(sample, cats), ensure_ascii=False, indent=2)[:3000])


def main():
    os.umask(0o027)
    if not shutil.which("curl"):
        sys.exit("curl nao encontrado.")
    token = load_token()
    cats = {"status": load_catalog(token, "/findings/statuses"),
            "priority": load_catalog(token, "/findings/priorities"),
            "type": load_catalog(token, "/findings/types")}
    try:
        findings = fetch_findings(token)
    except RuntimeError as e:
        sys.stderr.write(str(e) + "\n")
        return 1
    token = None

    if "--discover" in sys.argv:
        discover(None, cats, findings)
        return 0

    os.makedirs(SPOOL, exist_ok=True)
    stamp = datetime.now(TZ).strftime("%Y%m%d_%H%M%S")
    tmp_path = os.path.join(SPOOL, ".resonant_threat_{}.ndjson.part".format(stamp))
    final_path = os.path.join(SPOOL, "resonant_threat_{}.ndjson".format(stamp))
    written = skipped_type = skipped_brand = 0
    seen = set()
    with open(tmp_path, "w", encoding="utf-8") as fh:
        for f in findings:
            if not brand_ok(f):
                skipped_brand += 1
                continue
            if type_excluded(f, cats):
                skipped_type += 1
                continue
            doc = normalize(f, cats)
            if doc is None or doc["event"]["hash"] in seen:
                continue
            seen.add(doc["event"]["hash"])
            fh.write(json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n")
            written += 1

    if written == 0:
        os.remove(tmp_path)
        sys.stderr.write("Nada a escrever (findings={}, excl_tipo={}, excl_marca={}).\n".format(
            len(findings), skipped_type, skipped_brand))
        return 0
    os.rename(tmp_path, final_path)
    os.chmod(final_path, 0o640)
    sys.stderr.write("{}: findings={} escritos={} excl_tipo={} excl_marca={} -> {}\n".format(
        datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S"), len(findings), written,
        skipped_type, skipped_brand, final_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
