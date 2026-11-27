# Environment Definition YAML Schema

## What I Verified

I created `data/vuln_envs/jenkins.yml` and validated it with Ruby:

```bash
 ruby -e "
require 'yaml'
data = YAML.safe_load(File.read('data/vuln_envs/jenkins.yml'), permitted_classes: [Symbol])
puts 'Name: ' + data['name']
puts 'Variants: ' + data['variants'].map { |v| v['name'] }.inspect   # ← NEW: 'variants' list, .map
puts 'Ports: ' + data['shared']['ports'].inspect
puts 'Health check type: ' + data['shared']['health_check']['type']
"
```

Output:
```
Name: jenkins
Variants: ["2.361", "2.375"]
Ports: {"http"=>8080}
Health check type: http
```

## Directory Structure Example

```
data/
  vuln_envs/
    README.md          # Schema documentation
    jenkins.yml        # Jenkins with multiple profiles
```

## File Location
`data/vuln_envs/{name}.yml`

The `{name}` must match the `name` field inside the file.

## Design Principle: Profiles Over Files

A **single environment definition** represents one vulnerable service. It contains **one set of software versions** and **multiple configuration profiles** that describe different runtime states of that service.

**Why profiles instead of separate files?**
- **DRY**: Software versions are defined once, not duplicated across files
- **Discoverability**: All variants of a service live in one file
- **Relationship clarity**: `http-stopped` is explicitly a profile of `jenkins`, not a separate service
- **Maintainability**: Adding a new version requires editing one file, not N files

**Version strings represent actual software versions.** They are never suffixed to indicate configuration variants. The `profile` key selects the runtime configuration.

## Three-Level Configuration Hierarchy

When `test_env build` resolves an environment, it merges configuration in this order:

```
Level 1: Base shared (all profiles inherit)
    ↓
Level 2: Profile-specific overrides
    ↓
Level 3: Module-level overrides (minor tweaks)
```

This gives maximum reusability while allowing precise per-module customization.

## Decision Matrix: Profile vs. Module Override

| Scenario | Approach | Example |
|----------|----------|---------|
| Different runtime state (services on/off, different health check type) | **New profile** | `default` (HTTP on) vs `http-stopped` (HTTP off) |
| Different health check endpoint or expected status | **Module override** | Same profile, module overrides `health_check.path` |
| Different datastore default | **Module override** | Same profile, module overrides `datastore_defaults.TARGETURI` |
| Different credentials | **Module override** | Same profile, module overrides `credentials.default` |
| Service boots unconfigured and needs one-time setup before it's exploitable | **`shared.provision` (+ `verify`)** | WordPress image with no DB schema/admin account until the install wizard is submitted |

## Schema

### Top-Level Keys

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Machine-friendly identifier (matches filename) |
| `description` | String | Yes | Human-readable description |
| `variants` | Array | Yes | List of variant configurations |
| `shared` | Hash | Yes | Base configuration inherited by all profiles |
| `profiles` | Hash | Yes | Map of profile names to profile-specific overrides |

### variants Section

A list of configuration variants for this service. Each variant is a distinct
runnable configuration — typically a software version, but may also represent
different backends, plugins, or build options for the same version.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Unique identifier for this variant. Used in `test_env build VARIANT=...` |
| `version` | String | Yes | The actual software version. For information and future validation (e.g., Rapid7#21583) |
| `image` | String | Yes | OCI image reference |
| `build_args` | Hash | No | Docker build arguments |
| `default` | Boolean | No | If `true`, this variant is selected when no `VARIANT` is specified. Only one variant may be `default` |

Example:
```yaml
variants:
  - name: "2.361"
    version: "2.361"
    image: vulnhub/jenkins:2.361
    build_args:
      JENKINS_VERSION: "2.361"
    default: true

  - name: "2.361-postgres"
    version: "2.361"
    image: vulnhub/jenkins:2.361-pg
    build_args:
      JENKINS_VERSION: "2.361"
      DB_BACKEND: "postgresql"

  - name: "2.375"
    version: "2.375"
    image: vulnhub/jenkins:2.375
    build_args:
      JENKINS_VERSION: "2.375"
```
### shared Section

Base configuration inherited by all profiles. Any field here can be overridden by a profile or by module-level metadata.

#### ports (Required)
```yaml
shared:
  ports:
    http: 8080
```

#### health_check (Required in base or profile)
```yaml
shared:
  health_check:
    type: http
    path: /login
    expected_status: 200
    interval: 5
    timeout: 2
    retries: 12
```

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `type` | String | Yes | `http`, `tcp`, or `command` |
| `path` | String | If type=http | HTTP path to check |
| `expected_status` | Integer | No | Default: 200 |
| `match` | String | No | If type=http. Regex pattern the response body must match. Only checked once `expected_status` matches; use to distinguish "server responding" from "app actually ready" (e.g. an install wizard and a working login page can both return the same status) |
| `command` | String | If type=command | Command to execute |
| `expected_output` | String | If type=command | Regex pattern the command output must match |
| `interval` | Integer | No | Seconds between checks. Default: 5 |
| `timeout` | Integer | No | Seconds to wait. Default: 2 |
| `retries` | Integer | No | Max attempts. Default: 12 |

#### credentials (Optional)
```yaml
shared:
  credentials:
    default:
      username: admin
      password: admin
```

#### datastore_defaults (Optional)
```yaml
shared:
  datastore_defaults:
    TARGETURI: /script
```

#### provision (Optional)

Some images boot with the target process running but the application itself
not yet usable — e.g. a fresh WordPress container serves HTTP but has no
database schema or admin account until the install wizard is submitted.
`provision` describes a one-time setup action to run after `health_check`
passes and before the environment is registered as ready.

```yaml
shared:
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
    timeout: 10
```

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `type` | String | Yes | Provisioning mechanism. Currently only `http` is supported |
| `method` | String | No | HTTP verb when `type` is `http`. One of: `post`, `get`, `put`, `patch`. Default: `post` |
| `path` | String | Yes | Request path, sent to the primary mapped port (the container port mapped to `RPORT` in `port_mapping`) |
| `body` | Hash | No | Form fields, sent as `application/x-www-form-urlencoded`. Values may reference `{{ credentials.default.<key> }}`, which is resolved against the built datastore (e.g. `USERNAME`/`PASSWORD`). Only used for `post`, `put`, and `patch` |
| `timeout` | Integer | No | Seconds to wait for the request. Default: 10 |

A response status in the `200`–`399` range is treated as success. Anything
else (including a request error or timeout) fails the build; the container
is stopped and removed, matching the existing cleanup behavior for a failed
health check.

**Architectural decisions:** single stateless request only — no multi-step
flows (e.g. a form load to fetch a CSRF token before the real submit), no
session/cookie carryover between requests, and no non-HTTP provisioning
(e.g. running a setup command inside the container via `runtime.exec`, the
way `health_check`'s `command` type does). Extend `type` as new provisioning
shapes come up rather than building these speculatively.

#### verify (Optional)

Re-checks the environment after `provision` runs, confirming the setup
action actually took effect rather than just assuming success from the
HTTP status code. Uses the same shape and checker as `health_check`
(including the `match` field above), so it's commonly used to look for
content that only appears once setup is complete.

```yaml
shared:
  verify:
    type: http
    path: /wp-login.php
    expected_status: 200
    match: "user_login"
    interval: 3
    timeout: 2
    retries: 10
```

If `provision` is not defined, `verify` is ignored. If `provision` is
defined but `verify` is not, the environment is registered as ready as
soon as `provision` returns a `200`–`399` response, with no further check.

#### volumes (Optional)
```yaml
shared:
  volumes:
    jenkins_home:
      container_path: /var/jenkins_home
      persist: false
```

#### ci (Optional)
```yaml
shared:
  ci:
    exploit:
      payload: java/meterpreter/reverse_tcp
      options:
        LPORT: 4444
    validation:
      expected_session: true
      session_type: meterpreter
      expected_output: "uid="
      timeout: 120
```

**`ci.exploit`** — read and applied automatically by both `test_env build`
and `test_env exec`. If `payload` is set and differs from the module's
current `PAYLOAD`, it's applied via `set PAYLOAD ...` before the module
runs (this is what lets a definition steer around a module's own default
payload when that default is known not to work against the image).
Any keys under `options` are applied the same way.

Do not set `LHOST` here. The target runs inside a container network
namespace; a hardcoded `LHOST` (especially `127.0.0.1`) resolves to the
container itself, not the host, so the payload can never call back or be
fetched. Leaving `LHOST` unset lets Metasploit's own outbound-interface
auto-detection supply the host's real reachable address, which is what
actually works from inside a container.

| Key | Type | Required | Description |
|-----|------|----------|--------------|
| `payload` | String | No | Payload to select for this environment, if the module's default is unsuitable |
| `options` | Hash | No | Additional datastore keys to set (e.g. `LPORT`). Do not include `LHOST` |

**`ci.validation`** — read and checked by `test_env validate <ID>`, run
after `test_env exec <ID>`. This is the single definition of "did this
environment's exploit actually work," used identically whether a human
runs `validate` interactively or a future headless CI runner calls the
same resolution + check path - there is one source of truth, not a
YAML description alongside a separately-hand-maintained CI script.

| Key | Type | Required | Description |
|-----|------|----------|--------------|
| `expected_session` | Boolean | No | Default `true`. If `false`, `validate` passes without checking for a session at all |
| `session_type` | String | No | `meterpreter` or `shell`. If set, the created session's type must match |
| `expected_output` | String | No | Regex pattern that the output of the verification command on the session must match, e.g. `"uid="` or `"uid=\\d+"` |
| `timeout` | Integer | No | Seconds to wait for a session to appear before failing. Default: 120 |

`validate` reports `PASS` or `FAIL` with a specific reason. If no session
exists yet, run `test_env exec <ID>` first.

**Known limitation:** `validate` looks for the session in the current
process's `framework.sessions`. Metasploit sessions are process-local -
they exist only in the msfconsole process that opened them, with no
automatic cross-process visibility. `exec` and `validate` must therefore
run in the *same* msfconsole process/window. A future headless CI runner
would need to invoke both within a single `msfconsole -x` script (or
equivalent single-process automation), not as two independent CLI
invocations - this is a real constraint on any CI-alignment design here,
not just an interactive-usage quirk.

### profiles Section

Each profile is a key-value pair:
- **Key**: Profile name (e.g., `default`, `http-stopped`)
- **Value**: Hash that overrides or extends `shared`

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `description` | String | Yes | What this profile represents |
| `health_check` | Hash | No | Overrides base `shared.health_check` |
| `datastore_defaults` | Hash | No | Overrides base `shared.datastore_defaults` |
| `credentials` | Hash | No | Overrides base `shared.credentials` |
| `volumes` | Hash | No | Overrides base `shared.volumes` |
| `ci` | Hash | No | Overrides base `shared.ci` |
| `provision` | Hash | No | Overrides base `shared.provision` |
| `verify` | Hash | No | Overrides base `shared.verify` |

**Profile names** must match `[a-z0-9-]+`.

## Validation Rules

1. `name` must match filename (without `.yml`)
2. `variants` must be a non-empty list
3. Each variant must have a `name` and `image`
4. Variant `name` must be unique across all variants
5. At most one variant may have `default: true`
6. `shared.ports` must have at least one entry
7. `profiles` must have at least one entry
8. `profiles` must contain a `default` profile
9. Profile names must match `[a-z0-9-]+`
10. `health_check` must be defined in `shared` or in every profile
11. Module-level `overrides` are deep-merged into the final profile config

## Resolution & Merge Logic

When `test_env build` resolves an environment definition, the loader performs a **three-level deep merge**:

### Merge Order

| Level | Source | What It Contains |
|-------|--------|------------------|
| 1 | `shared` | Base configuration inherited by all profiles |
| 2 | `profiles[profile_name]` | Profile-specific overrides (minus `description`) |
| 3 | `VulnerableEnvironment['overrides']` | Module-level tweaks |

### Merge Rules

- **Hash fields** (e.g., `health_check`, `datastore_defaults`) are deep-merged: nested keys are combined, not replaced wholesale.
- **Scalar fields** (e.g., `image`, `build_args`) are replaced by the higher level.
- **The `description` key** in a profile is informational only and is excluded from the merge.

### Resolution Steps

1. Load the YAML definition file by `name`.
2. Validate that `variants` contains the requested `variant`.
3. Validate that `profiles` contains the requested `profile` (default: `'default'`).
4. Start with a copy of `shared`.
5. Deep-merge the selected profile's configuration into it.
6. Deep-merge the module's `VulnerableEnvironment['overrides']` (if any).
7. Attach the variant-specific `image`, `version`, and `build_args` from the matching variant in the `variants` list.

If the resolved config includes `provision`, it runs once the container
passes `health_check` and before the environment is registered. If
`verify` is also present, it runs immediately after `provision` succeeds.
A failure at either step aborts the build and tears down the container,
the same as a failed `health_check`.

### Error Cases

| Condition | Error |
|-----------|-------|
| Definition file not found | `"Definition not found: data/vuln_envs/{name}.yml"` |
| Variant not in `variants` | `"Variant '{variant}' not defined for '{name}'"` |
| Profile not in `profiles` | `"Profile '{profile}' not defined for '{name}'"` |
| No `default` profile exists | Validation fails at load time |

### Loader Interface (Week 3)

The `EnvironmentDefinitionLoader` exposes:

- `load(name)` — Parse and validate a definition file.
- `resolve(name, variant, profile, overrides)` — Return the fully merged configuration for a specific environment instance.
- `available_definitions` — List all `.yml` files in `data/vuln_envs/`.
## Module Metadata Integration

Modules reference a definition and optionally a profile. See [02-module-metadata.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/02-module-metadata.md) for the full `VulnerableEnvironment` schema.

```ruby
# Standard module — uses default variant and profile
'VulnerableEnvironment' => {
  'definition'      => 'jenkins',
  'default_variant' => '2.361',
  'port_mapping'    => { 8080 => 'RPORT' }
}

# Variant module — uses postgres variant
'VulnerableEnvironment' => {
  'definition'      => 'jenkins',
  'default_variant' => '2.361-postgres',
  'port_mapping'    => { 8080 => 'RPORT' }
}

# Module with profile override
'VulnerableEnvironment' => {
  'definition'      => 'jenkins',
  'default_variant' => '2.361',
  'profile'         => 'http-stopped',
  'port_mapping'    => { 8080 => 'RPORT' }
}

# Module with minor override — same profile, different health check
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


## Integration With Registry

Environment definitions are loaded by the plugin and used to:
1. Build/pull container images
2. Map container ports to host ports
3. Configure health checks
4. Run one-time provisioning and post-provision verification, if defined
5. Set module datastore defaults
6. Apply profile-specific overrides
7. Apply module-level overrides (if any)

See [03-database-schema.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/03-database-schema.md) for registry design.