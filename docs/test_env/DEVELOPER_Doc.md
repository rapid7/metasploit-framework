# Developer Documentation — Environment Definitions

> **Scope:** How to define, validate, and maintain vulnerable environment definitions for the `test_env` plugin.

---

## Table of Contents

1. [What Is an Environment Definition?](#what-is-an-environment-definition)
2. [Directory Structure](#directory-structure)
3. [Schema Reference](#schema-reference)
4. [The Three-Level Merge Hierarchy](#the-three-level-merge-hierarchy)
5. [Validation Rules](#validation-rules)
6. [How to Write a New Definition](#how-to-write-a-new-definition)
7. [Shared Definitions & Module Referencing](#shared-definitions--module-referencing)
8. [CI Metadata](#ci-metadata)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)

---

## What Is an Environment Definition?

An **environment definition** is a YAML file that describes a runnable, vulnerable service as an OCI-compliant container. It is the **single source of truth** for:

- Which container image to use
- Which ports the service exposes
- How to verify the service is ready (health checks)
- Default credentials and datastore options
- One-time provisioning steps (e.g., driving an install wizard)
- CI automation metadata (payload recommendations, validation expectations)

Definitions live in `data/vuln_envs/` and are referenced by exploit/auxiliary modules via the `VulnerableEnvironment` metadata key.

---

## Directory Structure

```
data/
  vuln_envs/
    README.md              # This documentation
    jenkins.yml            # Example: Jenkins CI
    activemq.yml           # Example: Apache ActiveMQ
    wordpress.yml          # Example: WordPress
    httpd.yml              # Example: Apache HTTP Server
    openssh.yml            # Example: OpenSSH
```

**File naming rule:** The filename (without `.yml`) **must** match the `name` field inside the file. The loader enforces this.

---

## Schema Reference

### Top-Level Keys

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | **Yes** | Machine-friendly identifier. Must match the filename. |
| `description` | String | **Yes** | Human-readable summary of what this service is. |
| `variants` | Array | **Yes** | List of runnable software versions / configurations. |
| `shared` | Hash | **Yes** | Base configuration inherited by **all** profiles. |
| `profiles` | Hash | **Yes** | Map of profile names to profile-specific overrides. |

---

### `variants` Section

Each variant represents a distinct runnable configuration — typically a software version, but may also represent different backends or build options for the same version.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | **Yes** | Unique identifier for this variant. Used in `test_env build VARIANT=...`. |
| `version` | String | **Yes** | The actual software version string (for information and validation). |
| `image` | String | **Yes** | OCI image reference (e.g., `docker.io/library/httpd:2.4.57`). |
| `build_args` | Hash | No | Docker/Podman build arguments if the image must be built locally. |
| `default` | Boolean | No | If `true`, this variant is selected when no `VARIANT` is specified. Only one variant may be `default`. |

**Example:**

```yaml
variants:
  - name: "2.361"
    version: "2.361"
    image: vulnhub/jenkins:2.361
    default: true

  - name: "2.361-postgres"
    version: "2.361"
    image: vulnhub/jenkins:2.361-pg
    build_args:
      DB_BACKEND: "postgresql"

  - name: "2.375"
    version: "2.375"
    image: vulnhub/jenkins:2.375
```

---

### `shared` Section

Base configuration inherited by every profile. Any field here can be overridden by a profile or by module-level metadata.

#### `shared.ports` (Required)

Maps logical port names to container ports. These are the ports the service listens on **inside** the container.

```yaml
shared:
  ports:
    http: 8080
    broker: 61616
```

> **Important:** These are container ports, not host ports. The `test_env build` command dynamically allocates free host ports and maps them.

---

#### `shared.health_check` (Required in `shared` or in every profile)

Defines how `test_env` waits for the service to become ready after the container starts.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `type` | String | **Yes** | `http`, `tcp`, or `command`. |
| `path` | String | If `type=http` | HTTP path to request. |
| `expected_status` | Integer | No | Expected HTTP status code. Default: `200`. |
| `match` | String | No | Regex pattern the response body must match. Use this to distinguish "server responding" from "app actually ready" (e.g., an install wizard vs. a login page). |
| `command` | String | If `type=command` | Shell command to execute **inside** the container. |
| `expected_output` | String | If `type=command` | Regex pattern the command output must match. |
| `interval` | Integer | No | Seconds between check attempts. Default: `5`. |
| `timeout` | Integer | No | Seconds to wait for a single check. Default: `2`. |
| `retries` | Integer | No | Maximum number of attempts. Default: `12`. |
| `credentials` | Hash | No | Basic Auth credentials for HTTP checks. Keys: `username`, `password`. |

**HTTP example:**

```yaml
health_check:
  type: http
  path: /api/jolokia/
  expected_status: 200
  interval: 5
  timeout: 2
  retries: 12
  credentials:
    username: admin
    password: admin
```

**TCP example:**

```yaml
health_check:
  type: tcp
  interval: 2
  timeout: 2
  retries: 10
```

**Command example:**

```yaml
health_check:
  type: command
  command: "mysqladmin ping"
  expected_output: "mysqld is alive"
  interval: 3
  timeout: 5
  retries: 20
```
> **Naming note:** `match` and `expected_output` both perform pattern matching, but they are named by context rather than by mechanism:
> - **`match`** — used for HTTP response bodies in `health_check` and `verify`.
> - **`expected_output`** — used for command stdout in `health_check` and for session verification output in `ci.validation`.
> Patterns are evaluated as Ruby regular expressions (not substrings), so anchors (`^`, `$`) and character classes work as expected.

---

#### `shared.credentials` (Optional)

Default credentials for the service. These are automatically merged into the module datastore as `USERNAME`, `PASSWORD`, etc.

```yaml
credentials:
  default:
    username: admin
    password: admin
```

---

#### `shared.datastore_defaults` (Optional)

Default datastore options for the module. These are applied automatically when the environment is built.

```yaml
datastore_defaults:
  TARGETURI: /script
  RHOSTS: 127.0.0.1
```

> **Note:** `RHOSTS` is automatically set to `127.0.0.1` by `test_env build`. You do not need to define it here unless you want a different value.

---

#### `shared.provision` (Optional)

Some images boot with the target process running but the application itself not yet usable. For example, a fresh WordPress container serves HTTP but has no database schema or admin account until the install wizard is submitted.

`provision` describes a one-time setup action that runs after the health check passes and before the environment is registered as ready.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `type` | String | **Yes** | Provisioning mechanism. Currently only `http` is supported. |
| `method` | String | No | HTTP verb when `type` is `http`. One of: `post`, `get`, `put`, `patch`. Default: `post`. |
| `path` | String | **Yes** | Request path, sent to the primary mapped port. |
| `body` | Hash | No | Form fields, sent as `application/x-www-form-urlencoded`. Values may reference `{{ credentials.default.<key> }}`, which is resolved against the built datastore. Only used for `post`, `put`, and `patch`. |
| `timeout` | Integer | No | Seconds to wait for the request. Default: `10`. |
| `run_once` | Boolean | No | If `true`, provisioning is skipped if a marker file exists inside the container (e.g., after a `stop`/`start` cycle). Default: `false`. |

**Example:**

```yaml
provision:
  type: http
  method: post
  path: /wp-admin/install.php?step=2
  body:
    weblog_title: "Vulnerable WP"
    user_name: "{{ credentials.default.username }}"
    admin_password: "{{ credentials.default.password }}"
    admin_password2: "{{ credentials.default.password }}"
    admin_email: "admin@example.com"
    blog_public: 0
    Submit: "Install WordPress"
  run_once: true
```

**Architectural constraints:**
- Single stateless request only — no multi-step flows.
- No session/cookie carryover between requests.
- No non-HTTP provisioning (e.g., no `runtime.exec` for setup commands).
- Extend `type` as new provisioning shapes come up rather than building speculatively.

**`run_once` behavior:**
When `run_once: true` is set, the provisioner creates a marker file (`/tmp/.msf_test_env_provisioned`) inside the container after the first successful provisioning. On subsequent operations (e.g., after `test_env start` restarts a stopped container), the provisioner checks for this marker and skips provisioning if it exists. This prevents duplicate form submissions or setup actions.

A failure (non-2xx/3xx response, timeout, or request error) aborts the build and tears down the container.

---

#### `shared.verify` (Optional)

Re-checks the environment after `provision` runs, confirming the setup action actually took effect. Uses the same shape as `health_check` (including the `match` field).

If `provision` is not defined, `verify` is ignored. If `provision` is defined but `verify` is not, the environment is registered as ready as soon as `provision` returns a `200`–`399` response.

**Restart behavior:** When a provisioned environment is stopped and later restarted via `test_env start`, the base `health_check` is skipped in favor of `verify`. This is because the container retains its filesystem state across restarts — the service is in its post-provision state, not its fresh-boot state. For example, a WordPress container that was provisioned during `build` will return `200` at `/` after a restart, not `302` to the install wizard.

```yaml
verify:
  type: http
  path: /wp-login.php
  expected_status: 200
  match: "user_login"
  interval: 3
  timeout: 2
  retries: 10
```

---

#### `shared.volumes` (Optional)

Defines volume mounts for the container.

```yaml
volumes:
  jenkins_home:
    container_path: /var/jenkins_home
    persist: false
```

If `host_path` is omitted, `test_env` creates a temporary directory that is cleaned up when the environment is removed.

---

#### `shared.ci` (Optional)

Metadata for CI-driven automated exploit verification. This is also read during interactive `test_env exec` to apply recommended payloads and options.

##### `ci.exploit`

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `payload` | String | No | Recommended payload for this environment. Applied if the module's current `PAYLOAD` differs. |
| `options` | Hash | No | Additional datastore keys to set (e.g., `LPORT`). |
| `force_exploit` | Boolean | No | If `true`, sets `ForceExploit true` on the module. |

> **Critical:** Do **not** set `LHOST` here. The target runs inside a container network namespace; a hardcoded `LHOST` (especially `127.0.0.1`) resolves to the container itself, not the host. Leave `LHOST` unset so Metasploit's outbound-interface auto-detection supplies the host's real reachable address.

**Example:**

```yaml
ci:
  exploit:
    payload: cmd/linux/http/x64/meterpreter/reverse_tcp
    options:
      LPORT: 4444
    force_exploit: true
```

##### `ci.validation`

Defines what "success" looks like for automated validation. Read by `test_env validate <ID>`.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `expected_session` | Boolean | No | Default `true`. If `false`, validation passes without checking for a session (used for auxiliary modules). |
| `session_type` | String | No | `meterpreter` or `shell`. If set, the created session's type must match. |
| `expected_output` | String | No | Regex pattern that the output of the verification command on the session must match, e.g., `"uid="` or `"uid=\\d+"`. |
| `timeout` | Integer | No | Seconds to wait for a session to appear. Default: `120`. |

**Example:**

```yaml
ci:
  validation:
    expected_session: true
    session_type: meterpreter
    expected_output: "uid="
    timeout: 120
```

> **Known limitation:** `validate` looks for sessions in the current msfconsole process's `framework.sessions`. Sessions are process-local — they exist only in the msfconsole that opened them. `exec` and `validate` must run in the **same** msfconsole process.

---

### `profiles` Section

Each profile is a runtime configuration of the service. Profiles override or extend `shared`.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `description` | String | **Yes** | What this profile represents. |
| `health_check` | Hash | No | Overrides base `shared.health_check`. |
| `datastore_defaults` | Hash | No | Overrides base `shared.datastore_defaults`. |
| `credentials` | Hash | No | Overrides base `shared.credentials`. |
| `volumes` | Hash | No | Overrides base `shared.volumes`. |
| `ci` | Hash | No | Overrides base `shared.ci`. |
| `provision` | Hash | No | Overrides base `shared.provision`. |
| `verify` | Hash | No | Overrides base `shared.verify`. |

**Profile names** must match `[a-z0-9-]+`.

**Every definition must contain a `default` profile.**

**Example:**

```yaml
profiles:
  default:
    description: Standard ActiveMQ; web console reachable via HTTP/Jolokia.

  broker-only:
    description: Web console not assumed reachable; only the broker port is health-checked.
    health_check:
      type: tcp
    ci:
      exploit:
        force_exploit: true
```

---

## The Three-Level Merge Hierarchy

When `test_env build` resolves an environment, configuration is merged in this order:

```
Level 1: shared (base configuration, inherited by all profiles)
    ↓
Level 2: profiles[profile_name] (profile-specific overrides)
    ↓
Level 3: Module-level overrides (VulnerableEnvironment['overrides'])
```

### Merge Rules

- **Hash fields** (e.g., `health_check`, `datastore_defaults`) are **deep-merged**: nested keys are combined, not replaced wholesale.
- **Scalar fields** (e.g., `image`, `build_args`) are **replaced** by the higher level.
- **The `description` key** in a profile is informational only and is excluded from the merge.

### Example: How the Rules Apply

Consider a definition where `shared`, the `broker-only` profile, and a module's `overrides` all contribute to the final `health_check` and `datastore_defaults`:

**Level 1 — `shared` (base):**
```yaml
health_check:
  type: http
  path: /api/jolokia/
  expected_status: 200
  interval: 5
  timeout: 2
  retries: 12
datastore_defaults:
  TARGETURI: /
```

**Level 2 — Profile `broker-only` overrides:**
```yaml
health_check:
  type: tcp
  interval: 2
ci:
  exploit:
    force_exploit: true
description: "Web console not assumed reachable"
```

**Level 3 — Module `overrides`:**
```ruby
'overrides' => {
  'health_check' => {
    'retries' => 20
  },
  'datastore_defaults' => {
    'TARGETURI' => '/console'
  }
}
```

**Resolved result:**
```yaml
health_check:
  type: tcp              # ← scalar replaced by profile
  path: /api/jolokia/    # ← preserved from shared (deep-merge)
  expected_status: 200   # ← preserved from shared (deep-merge)
  interval: 2            # ← scalar replaced by profile
  timeout: 2             # ← preserved from shared (deep-merge)
  retries: 20            # ← scalar replaced by module overrides
datastore_defaults:
  TARGETURI: /console    # ← scalar replaced by module overrides
ci:
  exploit:
    force_exploit: true  # ← added by profile (deep-merge)
```

Notice that:
- `health_check` is a **hash**, so keys are merged across all three levels rather than the profile or overrides replacing the entire block.
- `type`, `interval`, `retries`, and `TARGETURI` are **scalars**, so the highest-level value wins.
- `description` from the profile never appears in the resolved config because it is stripped before merging.

---

### Resolution Steps

1. Load the YAML definition file by `name`.
2. Validate that `variants` contains the requested `variant`.
3. Validate that `profiles` contains the requested `profile` (default: `'default'`).
4. Start with a copy of `shared`.
5. Deep-merge the selected profile's configuration into it.
6. Deep-merge the module's `VulnerableEnvironment['overrides']` (if any).
7. Attach the variant-specific `image`, `version`, and `build_args` from the matching variant.

---

## Validation Rules

The `EnvironmentDefinitionLoader` enforces the following rules at load time:

1. `name` must match the filename (without `.yml`).
2. `variants` must be a non-empty list.
3. Each variant must have a `name` and an `image`.
4. Variant `name` must be unique across all variants.
5. At most one variant may have `default: true`.
6. `shared.ports` must have at least one entry.
7. `profiles` must have at least one entry.
8. `profiles` must contain a `default` profile.
9. Profile names must match `[a-z0-9-]+`.
10. `health_check` must be defined in `shared` or in **every** profile.
11. Module-level `overrides` are deep-merged into the final profile config.

**Violation of any rule raises an `ArgumentError` with a descriptive message**, which is surfaced to the user by `test_env build`.

---

## How to Write a New Definition

### Step 1: Identify the Service

Determine:
- The vulnerable software and version(s)
- Available container images (Docker Hub, GitHub Container Registry, etc.)
- Exposed ports
- Whether the image is "ready on boot" or requires provisioning

### Step 2: Create the YAML File

Create `data/vuln_envs/{servicename}.yml`. The `name` field must match the filename.

### Step 3: Define Variants

List every version you want to support. At minimum, define one variant with `default: true`.

### Step 4: Define `shared.ports`

Map every port the service listens on inside the container.

### Step 5: Define Health Checks

Choose the simplest check that proves the service is **fully ready**, not just "accepting connections."

- For HTTP services: request a known endpoint and check status + optional `match`.
- For TCP services: `type: tcp` is sufficient.
- For services requiring auth: use the `credentials` sub-key under `health_check`.

### Step 6: Define Profiles (if needed)

If the service can run in different configurations (e.g., web console on vs. off), create profiles.

### Step 7: Add CI Metadata (optional but recommended)

Add `ci.exploit` and `ci.validation` so the environment can be used in automated verification.

### Step 8: Validate

Run:

```
load test_env.rb
test_env status
```

This validates all definitions and reports any schema errors.

---

## Shared Definitions & Module Referencing

### Principle: DRY (Don't Repeat Yourself)

Multiple modules targeting the same vulnerable service/version reference **a single shared environment definition**.

**Example:** Two ActiveMQ exploit modules share `activemq.yml`:

- `exploit/multi/http/apache_activemq_jolokia_rce` → uses variant `5.18.6`, profile `default`
- `exploit/multi/misc/apache_activemq_rce_cve_2023_46604` → uses variant `5.18.2`, profile `broker-only`

Both modules reference the same file but use different variants and profiles.

### Module Metadata

Modules declare their environment via `VulnerableEnvironment` inside `update_info()`:

```ruby
'VulnerableEnvironment' => {
  'definition'      => 'activemq',
  'default_variant' => '5.18.6',
  'profile'         => 'default',
  'port_mapping'    => { 8161 => 'RPORT' }
}
```

| Key | Required | Description |
|-----|----------|-------------|
| `definition` | **Yes** | Name of the YAML file (without `.yml`). |
| `default_variant` | **Yes** | Default variant to use if user does not specify `VARIANT=`. |
| `profile` | No | Profile to use. Default: `'default'`. |
| `port_mapping` | **Yes** | Hash mapping `{container_port => 'DATASTORE_OPTION'}`. At minimum, map the primary service port to `RPORT`. |
| `overrides` | No | Module-specific overrides deep-merged into the resolved config. |

**Example with overrides:**

```ruby
'VulnerableEnvironment' => {
  'definition'      => 'jenkins',
  'default_variant' => '2.361',
  'port_mapping'    => { 8080 => 'RPORT' },
  'overrides'       => {
    'health_check' => {
      'path' => '/script',
      'expected_status' => 403
    },
    'datastore_defaults' => {
      'TARGETURI' => '/script'
    }
  }
}
```

---

## CI Metadata

The `ci` block is designed to make environments self-testing. A CI pipeline (or a human running `test_env validate`) can determine success without hardcoding expectations.

### Typical CI Flow

1. `use exploit/multi/http/apache_activemq_jolokia_rce`
2. `test_env build`
3. `test_env exec 1`
4. `test_env validate 1`

Step 4 checks:
- Was a session created? (`expected_session`)
- Is it the right type? (`session_type`)
- Does `id` output contain `uid=`? (`expected_output`)

### For Auxiliary Modules

Set `expected_session: false` and `expected_output` to a substring expected in the scanner output or service response.

```yaml
ci:
  validation:
    expected_session: false
    expected_output: "Apache"
```

---

## Best Practices

### 1. Prefer HTTP Health Checks Over TCP

A TCP check only proves a port is open. An HTTP check proves the application layer is responding correctly. Use `match` to verify the response body contains expected content.

### 2. Use `provision` + `verify` for Install Wizards

If an image boots into an install wizard, define both `provision` (to submit the wizard) and `verify` (to confirm the login page appears afterward). Never register the environment as ready based solely on the install wizard being reachable.

### 3. Never Hardcode `LHOST` in `ci.exploit`

Metasploit's auto-detection handles this correctly. Hardcoding `127.0.0.1` causes payloads to call back to the container instead of the host.

### 4. Document Payload Incompatibilities

If a module's default payload does not work against your image, document why in a comment and set `ci.exploit.payload` to a working alternative.

### 5. Keep Variant Names Semantic

Use actual version numbers (e.g., `5.18.6`) rather than codenames. If you need a different backend for the same version, suffix descriptively (e.g., `5.18.2-postgres`).

### 6. Profile Names Describe Runtime State

Use profile names like `default`, `http-stopped`, `broker-only`, `minimal`. The name should tell the user what is different about this configuration.

### 7. Validate Early

Run `test_env status` after editing a definition. The loader validates the full schema and reports errors immediately.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Validation failed: name 'foo' does not match filename 'bar'` | `name` field ≠ filename | Make them identical. |
| `Variant 'X' not defined for 'Y'` | Module requests a variant not in the YAML | Add the variant or correct the module's `default_variant`. |
| `Profile 'X' not defined for 'Y'` | Module requests a profile not in the YAML | Add the profile or correct the module's `profile`. |
| `Port mapping mismatch: module maps port 8080 but environment only exposes ports: 80` | `port_mapping` references a port not in `shared.ports` | Add the port to `shared.ports` or correct the module's `port_mapping`. |
| `Health check timed out` | Service not ready within retry budget | Increase `retries` or `timeout`; verify the health check endpoint/path is correct. |
| `Provisioning failed` | Install wizard submission failed | Check `provision.path` and `provision.body` against the actual install wizard form fields. |
| `Post-provision verification failed` | `verify` check fails after provisioning | Ensure `verify.path` and `verify.match` reflect the post-install state. |

---

## Complete Example: `activemq.yml`

```yaml
name: activemq
description: Apache ActiveMQ Classic with Jolokia API

variants:
  - name: "5.18.6"
    version: "5.18.6"
    image: docker.io/apache/activemq-classic:5.18.6
    default: true

  - name: "5.18.2"
    version: "5.18.2"
    image: docker.io/dinifarb/activemq:5.18.2

shared:
  ports:
    web: 8161
    broker: 61616

  credentials:
    default:
      username: admin
      password: admin

  datastore_defaults:
    TARGETURI: /

  health_check:
    type: http
    path: /api/jolokia/
    expected_status: 200
    interval: 5
    timeout: 2
    retries: 12
    credentials:
      username: admin
      password: admin

  ci:
    exploit:
      payload: cmd/linux/http/x64/meterpreter/reverse_tcp
      options:
        LPORT: 4444
    validation:
      expected_session: true
      session_type: meterpreter
      expected_output: "uid="
      timeout: 120

profiles:
  default:
    description: Standard ActiveMQ; web console reachable via HTTP/Jolokia.

  broker-only:
    description: Web console not assumed reachable; only the broker port is health-checked.
    health_check:
      type: tcp
    ci:
      exploit:
        force_exploit: true
```