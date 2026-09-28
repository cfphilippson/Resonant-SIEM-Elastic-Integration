# Regra de detecção — alerta único por ciclo (ES|QL)

Objetivo: concentrar **todas as credenciais novas de um ciclo em um único alerta**, sem
flood no SOC nem fila interminável de incidentes.

## Como funciona

Como o `@timestamp` é o *first-seen* da coleta e a deduplicação por `event.hash` impede
reindexar credencial repetida, a janela da regra pega **apenas** as credenciais novas
daquele ciclo. A **Alert Suppression** agrupada por um campo de valor único colapsa todas
em um alerta só.

## Configuração da regra (Kibana → Security → Rules)

- **Rule type:** ES|QL
- **Alert Suppression:**
  - Suppress alerts by: `data_stream.dataset` (valor único → 1 alerta)
  - **Per rule execution** (1 alerta por rodada da regra)
  - If a suppression field is missing: **Suppress and group**
- **Schedule:** rodar após o coletor (ex.: a cada 8h, com look-back de 15m)

> Não agrupe por `user.name`/`url.original`: alta cardinalidade gera **um alerta por
> credencial** (o flood que se quer evitar). Para 1 alerta consolidado, agrupe por um campo
> de valor único.

## Query — variante A: credenciais corporativas

```esql
FROM logs-resonant_credentials_exposure-* METADATA _id, _index, _version
| WHERE data_stream.dataset == "resonant_credentials_exposure"
    AND user.domain == "minhaempresa.com.br"
| EVAL is_corporate = user.domain == "minhaempresa.com.br",
       days_since_breach = DATE_DIFF("day", resonant.breach_date, NOW())
| KEEP @timestamp, _id, _index, _version,
       user.name, user.email, user.domain,
       resonant.brand, resonant.source,
       resonant.finding.key, resonant.finding.title,
       resonant.breach_date, days_since_breach,
       credential.has_password, credential.password_length
| SORT resonant.breach_date DESC
```

## Query — variante B: credenciais de um domínio/serviço específico (ex.: loja)

```esql
FROM logs-resonant_credentials_exposure-* METADATA _id, _index, _version
| WHERE data_stream.dataset == "resonant_credentials_exposure"
    AND url.original RLIKE """https?://loja\.minhaempresa\.com\.br(:[0-9]+)?(/.*)?"""
| EVAL days_since_breach = DATE_DIFF("day", resonant.breach_date, NOW())
| KEEP @timestamp, _id, _index, _version,
       user.name, url.original, resonant.finding.key,
       resonant.source, resonant.breach_date, days_since_breach,
       credential.has_password, credential.password_length
| SORT resonant.breach_date DESC
```

## Observações

- `DATE_DIFF` sobre `resonant.breach_date` exige o campo mapeado como `date`
  (ver `01-component-template-mappings.json`).
- Ajuste `user.domain` / o regex de `url.original` para a sua marca/serviço.
- Para não gerar fila de casos: 1 caso por alerta agregado (não por credencial), ou trate o
  alerta como tarefa de "rodar reset em lote".
