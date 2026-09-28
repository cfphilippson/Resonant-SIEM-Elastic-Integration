#!/usr/bin/env python3
"""build_findings_dict.py - gera dicionario finding_uuid -> published_at para o translate do Logstash.

Consulta POST /findings/search (poucas dezenas de findings), extrai uuid + published_at
e escreve um CSV que o filtro translate carrega. Roda via cron, alinhado ao poll de credenciais.

Escrita atomica (tmp + rename) para o Logstash nunca ler CSV pela metade.
Python 3.6+, curl. Somente leitura na API.

Uso (cron):
  RESONANT_TOKEN_FILE=/etc/resonant/token DICT=/opt/logstash/config/dict/finding_published.csv \
    QUERY='brand:MINHAMARCA' python3 build_findings_dict.py

Token: env RESONANT_TOKEN, ou RESONANT_TOKEN_FILE (chmod 600), ou lê do proprio .conf via CONF=.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

BASE = "https://api.tempest.center/rest/monitoring/v2/findings/search"
CACERT = os.environ.get("CACERT", "/etc/pki/tls/certs/ca-bundle.crt")
DICT = os.environ.get("DICT", "/opt/logstash/config/dict/finding_published.csv")
QUERY = os.environ.get("QUERY", "").strip()
LIMIT = int(os.environ.get("LIMIT", "100"))      # max do endpoint findings/search
MAX_PAGES = int(os.environ.get("MAX_PAGES", "50"))
BRT = timezone(timedelta(hours=-3))


def load_token():
    tok = os.environ.get("RESONANT_TOKEN", "").strip()
    if not tok and os.environ.get("RESONANT_TOKEN_FILE"):
        p = os.environ["RESONANT_TOKEN_FILE"]
        if os.stat(p).st_mode & 0o077:
            sys.exit("Token file com permissao aberta; chmod 600 " + p)
        tok = open(p, encoding="utf-8").read().strip()
    if not tok and os.environ.get("CONF"):
        m = re.search(r'Bearer ([^"]+)"', open(os.environ["CONF"], encoding="utf-8").read())
        if m:
            tok = m.group(1).strip()
    if tok.lower().startswith("bearer "):
        tok = tok[7:].strip()
    if not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", tok or ""):
        sys.exit("Token ausente/invalido (RESONANT_TOKEN / RESONANT_TOKEN_FILE / CONF).")
    return tok


def post(token, page):
    payload = {"page": page, "limit": LIMIT, "order": {"published_at": -1}}
    if QUERY:
        payload["query"] = QUERY
    with tempfile.TemporaryDirectory(prefix="findings_") as tmp:
        bp = os.path.join(tmp, "b")
        cmd = ["curl", "-q", "-sS", "--proto", "=https", "--cacert", CACERT,
               "--connect-timeout", "15", "--max-time", "120", "-K", "-", "-X", "POST", BASE,
               "-H", "Accept: application/json", "-H", "Content-Type: application/json",
               "--data", json.dumps(payload), "-o", bp, "-w", "%{http_code}"]
        cfg = 'header = "Authorization: Bearer ' + token + '"\n'
        proc = subprocess.run(cmd, input=cfg, universal_newlines=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=130)
        code = int(proc.stdout.strip()) if proc.stdout.strip().isdigit() else 0
        raw = open(bp, encoding="utf-8", errors="replace").read() if os.path.exists(bp) else ""
    return code, raw


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


def norm_ts(raw):
    """published_at -> ISO8601 com tz. Sem tz, assume -03:00. Retorna None se vazio."""
    if not raw:
        return None
    s = str(raw).strip()
    if re.search(r"(Z|[+-]\d{2}:?\d{2})$", s):
        return s
    return s + "-03:00"


def main():
    token = load_token()
    mapping = {}
    for page in range(1, MAX_PAGES + 1):
        code, raw = post(token, page)
        if code == 404:
            break
        if code != 200:
            sys.stderr.write("findings/search pagina {}: HTTP {}\n".format(page, code))
            if not mapping:
                return 1
            break
        try:
            vals = values_of(json.loads(raw))
        except ValueError:
            break
        if not vals:
            break
        for f in vals:
            if not isinstance(f, dict):
                continue
            uuid = f.get("uuid")
            ts = norm_ts(f.get("published_at"))
            if uuid and ts:
                mapping[uuid] = ts
        if len(vals) < LIMIT:
            break
        time.sleep(0.3)
    token = None

    if not mapping:
        sys.stderr.write("Nenhum finding com published_at; dicionario nao atualizado.\n")
        return 1

    os.makedirs(os.path.dirname(DICT), exist_ok=True)
    tmp = DICT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for uuid, ts in sorted(mapping.items()):
            fh.write('{},{}\n'.format(uuid, ts))      # CSV: uuid,published_at (sem virgula no valor)
    os.replace(tmp, DICT)                              # rename atomico
    try:
        import shutil
        shutil.chown(DICT, group="logstash")
    except (LookupError, PermissionError):
        pass
    os.chmod(DICT, 0o640)
    sys.stderr.write("{}: {} findings -> {}\n".format(
        datetime.now(BRT).strftime("%Y-%m-%d %H:%M:%S"), len(mapping), DICT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
