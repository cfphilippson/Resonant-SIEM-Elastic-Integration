# Resonant DRP Threat → Elastic SIEM

Ingestão das Ameaças DRP (findings) da API Tempest Resonant / Prospero Suite num data stream do Elastic, via coletor Python + Logstash — com histórico de estado, paginação guiada pelo total e deduplicação idempotente.

- **Autor:** Carlos Quintas · SOC | CSIRT | SIEM Tech Leader · LinkedIn @carlosfpquintas
- **Componentes:** Python 3.6+ · curl · Logstash 8.x · Elasticsearch 8.x/9.x
- **Licença:** MIT
- **Versão:** 1.0 — outubro/2026

Projeto independente, sem relação oficial com a Tempest. Complementa o módulo de credenciais vazadas deste repositório (`resonant-elastic-drp/`): são integrações **apartadas**, com coletor, pipeline, data stream e API key próprios.

## Sumário

- [1. Visão geral](#1-visão-geral)
  - [1.1 Estrutura](#11-estrutura)
- [2. Decisões de arquitetura](#2-decisões-de-arquitetura)
  - [2.1 Coletor Python em vez de http_poller](#21-coletor-python-em-vez-de-http_poller)
  - [2.2 Findings mutáveis: histórico por estado](#22-findings-mutáveis-histórico-por-estado)
  - [2.3 Filtro de tipo e tradução de códigos](#23-filtro-de-tipo-e-tradução-de-códigos)
  - [2.4 digital_assets e indicadores](#24-digital_assets-e-indicadores)
  - [2.5 Segurança](#25-segurança)
- [3. API Resonant](#3-api-resonant)
- [4. Modelo de dados](#4-modelo-de-dados)
- [5. Instalação](#5-instalação)
  - [5.1 Elastic: templates e API key](#51-elastic-templates-e-api-key)
  - [5.2 Coletor](#52-coletor)
  - [5.3 Logstash](#53-logstash)
  - [5.4 Agendamento](#54-agendamento)
- [6. Validação e consultas](#6-validação-e-consultas)
  - [6.1 Regra de detecção sugerida](#61-regra-de-detecção-sugerida)
- [7. Solução de problemas](#7-solução-de-problemas)

## 1. Visão geral

O coletor consulta os findings publicados no módulo **Digital Risk Protection — Monitoramento** (as "Ameaças" `DRP-xxx` da console), filtra pelos tipos desejados, normaliza em ECS e grava NDJSON num spool. O Logstash lê o spool e indexa no data stream `logs-resonant_drp_threat-resonant`. O resultado serve de base para detecção, dashboards e acompanhamento do ciclo de vida de cada ameaça (publicação → takedown → encerramento).

```text
API Resonant (api.tempest.center)
   POST /findings/search            (paginação: 10 itens por página)
   GET  /findings/types|statuses|priorities   (catálogos)
        │
        ▼  cron */30 min (flock)
resonant_threat_collector.py
        │  filtra INCLUDE_TYPES, normaliza, calcula state_hash
        │  escrita atômica (.part → rename)
        ▼
<BASE_DIR>/spool_threat/resonant_threat_YYYYmmdd_HHMMSS.ndjson
        │  file input (mode=read)
        ▼
Logstash pipeline resonant_drp_threat  (@timestamp = coleta)
        │  output elasticsearch: op create, document_id = event.hash
        ▼
logs-resonant_drp_threat-resonant  (logsdb, ILM logs, failure store)
```

### 1.1 Estrutura

```text
resonant-drp-threat/
├── collector/resonant_threat_collector.py   # coleta, tradução de catálogos, filtro de tipo, state_hash
├── logstash/resonant_drp_threat.conf        # file input → data stream (placeholders)
├── elastic/
│   ├── 01-component-template-mappings.json  # mappings explícitos (flattened, long + *_name)
│   ├── 02-index-template.json               # data stream + herança de logs@settings
│   ├── 03-api-key-role.json                 # privilégio mínimo de escrita
│   └── queries-esql.md                      # consultas e regra de detecção (ES|QL)
├── deploy/resonant-threat-collector.cron    # agendamento + limpeza do spool
└── docs/Runbook_Resonant_DRP_Threat.docx    # este documento em Word
```

## 2. Decisões de arquitetura

### 2.1 Coletor Python em vez de http_poller

O endpoint `/findings/search` **ignora o `limit` solicitado** (devolve 10 itens por página) e não filtra por tipo no servidor. O coletor lê o `total` da resposta e pagina até o fim, com trava contra loop caso a API passe a ignorar o parâmetro `page`. Um `http_poller` só faria URLs fixas, sem paginação dinâmica.

### 2.2 Findings mutáveis: histórico por estado

- `event.hash` = `resonant.finding.state_hash` = SHA-256 de `uuid` + {status, priority, type, title, digital_assets, brand, source}.
- `document_id = event.hash` com operação `create`: re-coleta sem mudança devolve **409** (dedup); mudança de estado gera **um documento novo** — o índice guarda o histórico do finding.
- O `assignee` fica fora do hash para não gerar documentos por simples reatribuição.
- Estado atual = documento mais recente por `uuid` (consulta na seção 6).

### 2.3 Filtro de tipo e tradução de códigos

`INCLUDE_TYPES` (allowlist, código ou rótulo) tem precedência sobre `EXCLUDE_TYPES`. Os catálogos `/findings/statuses|priorities|types` são consultados a cada execução: o código fica em `status`/`priority`/`type` (`long`) e o rótulo em `*_name` (`keyword`). Se um catálogo falhar, a coleta segue apenas com o código. Para não duplicar com o módulo de credenciais, exclua o tipo de credenciais vazadas (ou use uma allowlist).

### 2.4 digital_assets e indicadores

`digital_assets` é mapeado como `flattened` (estrutura não documentada, sem mapping explosion). Como a API entrega uma **lista de strings** e `flattened` exige objeto na raiz, o coletor encapsula em `{"items": [...]}`. URLs, domínios e IPs (com refang de `hxxp` e `[.]`, inclusive `.onion`) são extraídos para `resonant.finding.indicators.*`, `related.hosts`, `related.ip` e `url.original`.

> [!WARNING]
> **Indicadores não são, necessariamente, IOCs maliciosos**
> Em findings de dados expostos a URL é a **origem do vazamento** (ex. `github.com`), não infraestrutura do atacante. Use esses campos para pivô e triagem; para indicator match contra proxy/DNS, exclua domínios de hospedagem legítima.

### 2.5 Segurança

- Token passado ao curl via stdin (`-K -`), nunca em argv/ps; o coletor recusa arquivo de token com permissão aberta.
- Chaves com aparência de segredo (pass, token, cookie, cpf, cnpj…) são removidas recursivamente de `digital_assets`.
- API key do Elastic dedicada, com privilégio mínimo (`auto_configure` + `create_doc`) restrito ao data stream, armazenada no keystore do Logstash — nunca em texto no `.conf`.
- Evite filtrar por marca: findings de terceiros (marca vazia, ex. vazamentos em sites de extorsão) são relevantes para risco de supply chain.

## 3. API Resonant

| Endpoint | Método | Uso |
|---|---|---|
| `/rest/monitoring/v2/findings/search` | POST | Lista findings. Corpo: `{"page":N,"limit":100,"order":{"published_at":-1}}`; resposta com `total` e `values` |
| `/rest/monitoring/v2/findings/types` | GET | Catálogo de tipos |
| `/rest/monitoring/v2/findings/statuses` | GET | Catálogo de status |
| `/rest/monitoring/v2/findings/priorities` | GET | Catálogo de prioridades |

- Autenticação: `Authorization: Bearer <token>`.
- Campos por finding: `uuid, key, published_at, title, status, priority, type, brand, source, assignee, digital_assets`. Não há campo de última atualização — a mudança é detectada pelo `state_hash`.
- A resposta pode vir como objeto ou como lista com um objeto; o coletor trata ambos.
- Os códigos numéricos variam por tenant: confirme-os com `--discover` (exemplo: `6` = Exposed Data).

Teste rápido de consumo:

```bash
RTOK=$(cat <BASE_DIR>/token); curl -sS --http1.1 --cacert /etc/pki/tls/certs/ca-bundle.crt -H "Authorization: Bearer $RTOK" -H "Content-Type: application/json" -X POST "https://api.tempest.center/rest/monitoring/v2/findings/search" --data '{"page":1,"limit":100,"order":{"published_at":-1}}' -w 'HTTP %{http_code}\n' -o /tmp/thr.json; unset RTOK
```

## 4. Modelo de dados

| Campo | Tipo | Conteúdo |
|---|---|---|
| `@timestamp` | date | Hora da coleta (observação do estado) |
| `event.hash` | keyword | state_hash; também é o `_id` |
| `resonant.finding.uuid` / `key` | keyword | Identificador e código `DRP-xxx` |
| `resonant.finding.title` | keyword + `.text` | Título |
| `resonant.finding.published_at` | date | Publicação pela Tempest |
| `resonant.finding.status` / `status_name` | long / keyword | Código e rótulo |
| `resonant.finding.priority` / `priority_name` | long / keyword | Código e rótulo |
| `resonant.finding.type` / `type_name` | long / keyword | Código e rótulo |
| `resonant.finding.digital_assets` | flattened | `{items: [...]}` |
| `resonant.finding.indicators.urls\|domains\|ips` | keyword / ip | Indicadores extraídos |
| `resonant.brand` / `source` / `assignee` | keyword | Marca, fonte e responsável na Tempest |
| `related.hosts` / `related.ip` / `url.original` | keyword / ip / wildcard | Pivô ECS |

## 5. Instalação

### 5.1 Elastic: templates e API key

Aplique os templates **antes** da primeira ingestão (Kibana → Dev Tools). O componente da integração fica por último em `composed_of` para prevalecer sobre `logs@custom`.

```json
PUT _component_template/resonant-drp-threat-mappings
{
  "template": {
    "mappings": {
      "properties": {
        "resonant": {
          "properties": {
            "brand":    { "type": "keyword" },
            "source":   { "type": "keyword" },
            "assignee": { "type": "keyword" },
            "finding": {
              "properties": {
                "uuid":           { "type": "keyword" },
                "key":            { "type": "keyword" },
                "title":          { "type": "keyword", "ignore_above": 1024,
                                    "fields": { "text": { "type": "match_only_text" } } },
                "published_at":   { "type": "date" },
                "state_hash":     { "type": "keyword" },
                "status":         { "type": "long" },
                "status_name":    { "type": "keyword" },
                "priority":       { "type": "long" },
                "priority_name":  { "type": "keyword" },
                "type":           { "type": "long" },
                "type_name":      { "type": "keyword" },
                "digital_assets": { "type": "flattened", "ignore_above": 2048 },
                "indicators": {
                  "properties": {
                    "urls":    { "type": "keyword", "ignore_above": 2048 },
                    "domains": { "type": "keyword" },
                    "ips":     { "type": "ip" }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "_meta": { "description": "Tempest Resonant DRP Threat (findings)" }
}
```

```json
PUT _index_template/logs-resonant_drp_threat
{
  "index_patterns": ["logs-resonant_drp_threat-*"],
  "data_stream": {},
  "priority": 200,
  "composed_of": [
    "logs@mappings",
    "logs@settings",
    "ecs@mappings",
    "logs@custom",
    "logs-resonant_drp_threat@custom",
    "resonant-drp-threat-mappings"
  ],
  "ignore_missing_component_templates": ["logs@custom", "logs-resonant_drp_threat@custom"],
  "_meta": { "description": "Tempest Resonant DRP Threat", "managed_by": "resonant" }
}

POST _index_template/_simulate_index/logs-resonant_drp_threat-resonant
```

Na simulação, confira `index.lifecycle.name`, `published_at` como `date` e `digital_assets` como `flattened`.

> [!CAUTION]
> **Failure store**
> Em stacks recentes o template de logs habilita o failure store: documento com erro de mapping **não** volta como erro ao Logstash (HTTP 200), e sim para `<data stream>::failures`. Valide sempre `GET logs-resonant_drp_threat-resonant::failures/_search` após mudanças.

```json
POST _security/api_key
{
  "name": "logstash-resonant-drp-threat-write",
  "role_descriptors": {
    "resonant_drp_threat_writer": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["logs-resonant_drp_threat-resonant*"],
          "privileges": ["auto_configure", "create_doc"]
        }
      ]
    }
  },
  "metadata": { "integration": "tempest-resonant-drp-threat" }
}
```

> [!WARNING]
> **Formato no keystore**
> Grave o campo `encoded` da resposta (base64) ou `id:api_key`, sem aspas e sem espaços. Valores com aspas ou quebra de linha geram `Invalid api_key format` no start do pipeline.

### 5.2 Coletor

```bash
BASE_DIR=/opt/logstash/config/resonant
install -D -m 0750 collector/resonant_threat_collector.py "$BASE_DIR/resonant_threat_collector.py"
install -d -m 0755 "$BASE_DIR/spool_threat"
umask 077; printf '%s' 'SEU_TOKEN_RESONANT' > "$BASE_DIR/token"; chmod 600 "$BASE_DIR/token"

# descoberta (não grava nada): catálogos, distribuição por tipo e amostra normalizada
RESONANT_TOKEN_FILE=$BASE_DIR/token python3 $BASE_DIR/resonant_threat_collector.py --discover

# primeira coleta
RESONANT_TOKEN_FILE=$BASE_DIR/token SPOOL=$BASE_DIR/spool_threat INCLUDE_TYPES=6 python3 $BASE_DIR/resonant_threat_collector.py
```

| Variável | Padrão | Descrição |
|---|---|---|
| `RESONANT_TOKEN_FILE` | — | Arquivo do token (permissão 600 obrigatória) |
| `SPOOL` | `/var/spool/resonant_threat` | Diretório de saída do NDJSON |
| `INCLUDE_TYPES` | vazio (todos) | Allowlist de tipos (código ou rótulo) |
| `EXCLUDE_TYPES` | vazio | Denylist aplicada após a allowlist |
| `BRAND` | vazio | Filtro por marca (evite; descarta terceiros) |
| `CACERT` | `/etc/pki/tls/certs/ca-bundle.crt` | Bundle de CAs |
| `MAX_PAGES` / `REQ_MAX_TIME` / `MAX_IOCS` | 1000 / 120 / 200 | Teto de páginas, timeout (s) e indicadores por finding |

> [!WARNING]
> **Colando o script num editor**
> No `vi`, use `:set paste` antes de colar: o autoindent acumula a indentação e quebra o Python (`IndentationError`). Confira com `python3 -m py_compile` e `grep -c $'\r'` (CRLF deve ser 0).

### 5.3 Logstash

Ajuste os placeholders `<BASE_DIR>`, `<LOG_DIR>` e `<ELASTIC_HOST>`, registre um `pipeline.id` próprio no `pipelines.yml` (nunca concatene configs com glob) e grave a API key no keystore:

```ruby
# resonant_drp_threat.conf - Ameacas DRP (findings) Tempest Resonant -> Elastic.
# Ajuste os placeholders <BASE_DIR>, <LOG_DIR> e <ELASTIC_HOST> antes de subir.
# Pipeline APARTADO do resonant_credentials.conf (pipeline.id proprio no pipelines.yml).
# @timestamp = hora da coleta (observacao do estado). Historico por mudanca de estado:
# document_id = event.hash (uuid + estado) com op create -> re-coleta sem mudanca = 409.

input {
  file {
    path           => "<BASE_DIR>/spool_threat/resonant_threat_*.ndjson"
    mode           => "read"
    start_position => "beginning"
    codec          => json
    sincedb_path   => "<BASE_DIR>/sincedb_resonant_threat"
    file_completed_action   => "log"
    file_completed_log_path => "<LOG_DIR>/resonant_threat_completed.log"
    tags           => ["resonant", "drp-threat"]
  }
}

filter {
  ruby {
    code => '
      now = Time.now.utc
      event.set("@timestamp", LogStash::Timestamp.new(now))
      event.set("[event][ingested]", now.strftime("%Y-%m-%dT%H:%M:%S.%LZ"))
    '
  }
  mutate {
    add_field    => { "[ecs][version]" => "8.11.0" }
    remove_field => ["host", "log", "message", "path", "[event][original]"]
  }
}

output {
  elasticsearch {
    hosts   => ["https://<ELASTIC_HOST>:443"]
    api_key => "${api_key_threat}"     # keystore: logstash-keystore add api_key_threat (encoded ou id:api_key)
    data_stream           => "true"
    data_stream_type      => "logs"
    data_stream_dataset   => "resonant_drp_threat"
    data_stream_namespace => "resonant"
    document_id => "%{[event][hash]}"
    ssl_enabled => true
  }
}
```

```bash
# pipelines.yml
- pipeline.id: resonant_drp_threat
  path.config: "/opt/logstash/config/pipelines/resonant_drp_threat.conf"
  pipeline.workers: 1

# keystore + teste de sintaxe
/opt/logstash/bin/logstash-keystore --path.settings /opt/logstash/config add api_key_threat
/opt/logstash/bin/logstash --path.settings /opt/logstash/config --path.data /tmp/ls-test -t -f /opt/logstash/config/pipelines/resonant_drp_threat.conf
```

### 5.4 Agendamento

```bash
# /etc/cron.d/resonant-threat-collector
# Coleta a cada 30 minutos (flock evita execucoes sobrepostas). Ajuste caminhos e INCLUDE_TYPES.
*/30 * * * * root flock -n /tmp/resonant_threat.lock env RESONANT_TOKEN_FILE=<BASE_DIR>/token SPOOL=<BASE_DIR>/spool_threat INCLUDE_TYPES=6 /usr/bin/python3 <BASE_DIR>/resonant_threat_collector.py >> <LOG_DIR>/resonant_threat_collector.log 2>&1

# Limpeza do spool: NDJSON com mais de 7 dias
15 3 * * * root find <BASE_DIR>/spool_threat -name 'resonant_threat_*.ndjson' -mtime +7 -delete
```

- **Coleta** a cada 30 minutos; `flock` impede sobreposição.
- **Ingestão** contínua: o pipeline lê cada NDJSON novo em segundos, venha do cron ou de execução manual.
- **Latência** típica: publicação → índice em até ~31 minutos.

## 6. Validação e consultas

```bash
# Logstash: eventos e resultado do bulk
curl -s localhost:9600/_node/stats/pipelines/resonant_drp_threat | python3 -c 'import json,sys;p=json.load(sys.stdin)["pipelines"]["resonant_drp_threat"];print("in:",p["events"]["in"],"out:",p["events"]["out"]);[print(o.get("documents",{})) for o in p["plugins"]["outputs"]]'

# Elasticsearch
GET logs-resonant_drp_threat-resonant/_count
GET logs-resonant_drp_threat-resonant::failures/_search?size=3
```

**Idempotência:** numa segunda coleta sem mudanças, o Logstash reporta `non_retryable_failures` igual ao número de findings (os 409 da dedup) e o `_count` não muda. Esse contador cresce a cada ciclo — exclua este pipeline de monitoramentos de saúde baseados nele.

O `@timestamp` é a hora da coleta: no Discover amplie o período e filtre a data real da ameaça por `resonant.finding.published_at`.

```esql
// estado atual por finding
FROM logs-resonant_drp_threat-*
| INLINE STATS last_ts = MAX(@timestamp) BY resonant.finding.uuid
| WHERE @timestamp == last_ts
| KEEP resonant.finding.key, resonant.finding.published_at, resonant.finding.priority_name,
       resonant.finding.status_name, resonant.finding.title, resonant.finding.indicators.urls
| SORT resonant.finding.published_at DESC

// linha do tempo de um finding
FROM logs-resonant_drp_threat-*
| WHERE resonant.finding.key == "DRP-123"
| KEEP @timestamp, resonant.finding.status_name, resonant.finding.priority_name, resonant.finding.state_hash
| SORT @timestamp ASC
```

### 6.1 Regra de detecção sugerida

```esql
FROM logs-resonant_drp_threat-* METADATA _id, _index, _version
| WHERE resonant.finding.published_at >= NOW() - 24 hours
```

- Intervalo 30 min, look-back 5 min (`from: now-35m`).
- Supressão por `resonant.finding.uuid` por 30 dias: mudanças de estado logo após a publicação não realertam.
- `severity_mapping` em `resonant.finding.priority_name` (ex. `Medium` → medium, `High` → high, `Critical` → critical).
- O filtro em `published_at` evita alertas na carga histórica inicial.

## 7. Solução de problemas

| Sintoma | Causa | Ação |
|---|---|---|
| `Invalid api_key format` | Valor do keystore com aspas, espaço ou incompleto | Regravar com `encoded`; validar com `GET _security/_authenticate` |
| Coletor grava só 10 findings | Paginação interrompida (10 por página) | Paginação guiada pelo `total`; conferir `findings coletados: N/N` |
| Logstash `in = out`, `_count` menor | Documentos no failure store | `GET ...::failures/_search` e ler `error.message` |
| `digital_assets` no failure store | Lista na raiz de campo `flattened` | Gravar `{"items": [...]}`; descartar NDJSON antigo |
| `PKIX path building failed` / curl 60 | CA não encontrada | Ajustar `CACERT` |
| `403` / `security_exception` | API key sem escopo no data stream | Revisar `role_descriptors` |
| Discover vazio | Time picker curto | Ampliar período; filtrar por `published_at` |
