# Consultas e regra de detecção (ES|QL)


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

