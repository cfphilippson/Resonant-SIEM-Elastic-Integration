# Resonant-SIEM-Elastic-Integration
Ingestão do feed de credenciais vazadas (Digital Risk Protection) da API Tempest Resonant / Prospero Suite para um data stream do Elastic, via coletor Python + Logstash — com privacidade por design (signal-only), paginação dinâmica e deduplicação idempotente.
Autor: Carlos Quintas · SOC | CSIRT | SIEM Tech Leader · LinkedIn @carlosfpquintas

## Módulos

| Módulo | Feed da API Resonant | Data stream |
|---|---|---|
| [`resonant-elastic-drp/`](resonant-elastic-drp/) | Credenciais vazadas (`/leaked_credentials`) | `logs-resonant_credentials_exposure-resonant` |
| [`resonant-drp-threat/`](resonant-drp-threat/) | Ameaças DRP / findings (`/findings/search`) — ex. Exposed Data | `logs-resonant_drp_threat-resonant` |

Os módulos são independentes (coletor, pipeline, data stream e API key próprios) e compartilham apenas o token da API.

Arquitetura

Mostrar Imagem

API Resonant ──(coletor: findings + credenciais, paginação completa)──► NDJSON no spool
                                                                             │
                                                     Logstash (file input) ──┘
                                                                             ▼
                              data stream  logs-resonant_credentials_exposure-resonant

Princípios:

Coletor Python, não http_poller. A API é paginada por page (limit fixo de 1000), não tem parâmetro order e a página 1 retorna os registros mais antigos. O coletor lê o total e pagina até o fim — acompanha o crescimento do feed sem teto fixo.
Signal-only. Senha, CPF e CNPJ nunca são indexados — viram has_password, password_length, national_id.has_cpf/has_cnpj. O índice não vira um segundo vazamento.
Enriquecimento da Ameaça. Cada credencial é carimbada com o finding correspondente (resonant.finding.key = DRP-xxx, além de title, status, priority, published_at).
Idempotência. document_id = event.hash (fingerprint de conteúdo) com op create; re-coletas devolvem 409 e não duplicam.
Estrutura do repositório
.
├── collector/
│   ├── resonant_cred_collector.py   # coleta paginada + redação + enriquecimento da Ameaça
│   └── build_findings_dict.py       # (opcional) dicionário finding_uuid → published_at
├── logstash/
│   └── resonant_credentials.conf    # file input → data stream (com placeholders)
├── elastic/
│   ├── 01-component-template-mappings.json  # campos de data (published_at, breach_date, created_at)
│   ├── 02-index-template.json               # amarra o data stream + ILM logs
│   ├── 03-api-key-role.json                 # privilégio mínimo de escrita
│   └── detection-rule-esql.md               # regra de alerta único por ciclo (ES|QL)
├── deploy/
│   └── resonant-collector.cron      # agendamento + limpeza do spool
└── docs/
    ├── fluxo.png
    └── fluxo-dark.png
Pré-requisitos
Logstash, Python 3.6+ e curl no servidor.
Bundle de CAs do sistema para o TLS da API (ex.: /etc/pki/tls/certs/ca-bundle.crt).
Token de integração da Resonant.
API key do Elastic no formato id:api_key com privilégio de escrita (ver elastic/03-api-key-role.json).
Instalação rápida
bash
BASE_DIR=/opt/logstash/config/resonant
install -D -m 0750 collector/resonant_cred_collector.py "$BASE_DIR/resonant_cred_collector.py"
install -D -m 0644 logstash/resonant_credentials.conf   /opt/logstash/config/pipelines/resonant_credentials.conf
install -d -m 0755 "$BASE_DIR/spool"

# token (nunca versione)
umask 077; printf '%s' 'SEU_TOKEN_RESONANT' > "$BASE_DIR/token"; chmod 600 "$BASE_DIR/token"

# api key no keystore do Logstash (formato id:api_key)
/opt/logstash/bin/logstash-keystore --path.settings /opt/logstash/config add api_key

Ajuste os placeholders do .conf (<BASE_DIR>, <LOG_DIR>, <ELASTIC_HOST>), registre o pipeline no pipelines.yml e instale o cron:

bash
install -m 0644 deploy/resonant-collector.cron /etc/cron.d/resonant-collector
Elastic — templates e datas

Aplique os templates antes da primeira carga (Kibana → Dev Tools):

PUT _component_template/resonant-finding-mappings   # corpo: elastic/01-component-template-mappings.json
PUT _index_template/resonant-credentials            # corpo: elastic/02-index-template.json

Isso mapeia published_at, breach_date e created_at como date — o Kibana então exibe no fuso configurado (a API entrega em UTC). Sem isso, as datas ficam como keyword e aparecem em UTC cru.

Primeira carga
bash
RESONANT_TOKEN_FILE=$BASE_DIR/token QUERY='brand:MINHAMARCA' SPOOL=$BASE_DIR/spool \
  /usr/bin/python3 $BASE_DIR/resonant_cred_collector.py
systemctl restart logstash

Validação:

GET /logs-resonant_credentials_exposure-resonant/_count
GET /logs-resonant_credentials_exposure-resonant/_search?size=1&q=resonant.finding.key:*
Detecção — alerta único por ciclo

Ver elastic/detection-rule-esql.md. Resumo: regra ES|QL com Alert Suppression agrupando por data_stream.dataset (valor único), per rule execution → um único alerta consolidando todas as credenciais novas do ciclo, sem flood.

Variáveis do coletor
Var	Padrão	Função
QUERY	"" (todas)	filtro campo:valor da API (ex.: brand:MINHAMARCA)
SPOOL	/var/spool/resonant	destino do NDJSON
CACERT	/etc/pki/tls/certs/ca-bundle.crt	bundle de CAs para o TLS da API
RESONANT_TOKEN / RESONANT_TOKEN_FILE	—	token (env ou arquivo chmod 600)
MAX_PAGES	1000	teto de segurança de páginas
PAGE_MAX_TIME	600	timeout por página (s)
Modelo de dados

logs-resonant_credentials_exposure-resonant:

@timestamp (first-seen), event.hash, event.ingested
user.email / user.name / user.domain, url.original
credential.has_password, credential.password_length, credential.created_at, credential.national_id.has_cpf/has_cnpj
resonant.brand, resonant.source, resonant.breach_date, resonant.exposure_scope, resonant.stealer_family, resonant.malware_path
resonant.finding.{uuid,key,title,status,priority,type,published_at} (a Ameaça DRP-xxx)
Uso downstream (resposta a incidente)

Cruze user.email contra os sign-in logs do provedor de identidade (ex.: Entra ID) para priorizar reset forçado + revogação de sessão. A validade da credencial se afere por telemetria de autenticação — não tentando logar com a senha vazada. A Ameaça (resonant.finding.key) permite pivotar credencial ↔ finding.

Segurança
Nunca versione token, API key ou NDJSON (contêm dados de findings). Ver .gitignore.
Token em arquivo chmod 600; rotacione periodicamente.
API key com o privilégio mínimo de elastic/03-api-key-role.json.
Aviso

Projeto independente, sem relação com a Tempest Security Intelligence. "Resonant" e "Prospero Suite" são marcas de seus respectivos donos. Endpoints e campos da API podem mudar.

Licença

MIT — ver LICENSE.
