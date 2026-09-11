# User Documentation — `test_env`

> **Scope:** How to use the `test_env` plugin to provision, manage, and exploit vulnerable environments within Metasploit.

---

## Table of Contents

1. [What Is `test_env`?](#what-is-test_env)
2. [Prerequisites](#prerequisites)
3. [Loading the Plugin](#loading-the-plugin)
4. [Quick Start](#quick-start)
5. [Command Reference](#command-reference)
6. [Typical Workflows](#typical-workflows)
7. [Environment Variables & Options](#environment-variables--options)
8. [Understanding the Registry](#understanding-the-registry)
9. [CI Integration](#ci-integration)
10. [Troubleshooting](#troubleshooting)

---

## What Is `test_env`?

`test_env` is a Metasploit plugin that automates the provisioning of vulnerable environments for exploit and auxiliary modules. Instead of manually building Docker images, looking up port numbers, and configuring datastore options, `test_env` does it all in a single command:

```
msf > use exploit/multi/http/apache_activemq_jolokia_rce
msf exploit(...) > test_env build
[+] Environment ready.
[+] Environment ID: 1
    RHOSTS       => 127.0.0.1
    RPORT        => 49152
    TARGETURI    => /
    USERNAME     => admin
    PASSWORD     => admin
Suggested: exploit RHOSTS=127.0.0.1 RPORT=49152 TARGETURI=/ USERNAME=admin PASSWORD=admin
```

**Key features:**
- **One-command provisioning**: Builds, launches, health-checks, and configures the module automatically.
- **Dynamic port allocation**: Finds free host ports automatically; supports multiple concurrent environments.
- **Persistent tracking**: Environments are tracked across `msfconsole` restarts via a YAML registry.
- **Runtime abstraction**: Works with Docker (primary) and Podman (including rootless).
- **Automated exploit execution**: `test_env exec <ID>` loads the module, applies the correct datastore, and runs the exploit.
- **Validation**: `test_env validate <ID>` checks whether the exploit produced the expected session and output.

---

## Prerequisites

### Required

- **Metasploit Framework** (msfconsole)
- **Docker** or **Podman** installed and available in your `$PATH`

### Optional

- **Podman networking backends** (`pasta` or `slirp4netns`) if using rootless Podman

### Verify Your Setup

```bash
# Check Docker
docker version

# Or check Podman
podman version
```

---

## Loading the Plugin

### Manual Load

From within `msfconsole`:

```
msf > load test_env
[*] TestEnv plugin loaded. Runtime: docker
[*] Successfully loaded plugin: test_env
```

If no runtime is found:

```
[-] TestEnv plugin loaded, but no container runtime found.
[-] Install Docker or Podman to use test_env.
```

### Automatic Load (Optional)

Add to your `~/.msf4/msfconsole.rc`:

```
load test_env
```

---

## Quick Start

### 1. Select a Module

```
msf > use exploit/multi/http/apache_activemq_jolokia_rce
```

### 2. Build the Environment

```
msf exploit(...) > test_env build
```

This will:
1. Detect the container runtime (Docker or Podman)
2. Pull the required image
3. Allocate free host ports
4. Launch the container bound to `127.0.0.1`
5. Wait for health checks to pass
6. Apply datastore options (`RHOSTS`, `RPORT`, credentials, etc.)
7. Register the environment and display the suggested exploit command

### 3. Run the Exploit

```
msf exploit(...) > test_env exec 1
```

Or manually:

```
msf exploit(...) > exploit
```

### 4. Validate (Optional)

```
msf exploit(...) > test_env validate 1
[+] PASS: environment 1 validated successfully against activemq's ci.validation.
```

### 5. Clean Up

```
msf exploit(...) > test_env remove 1
```

Or remove all:

```
msf exploit(...) > test_env remove-all
```

---

## Command Reference

### `test_env build [VARIANT=...] [PROFILE=...] [RPORT=...]`

Build and launch the vulnerable environment for the **active module**.

**Options:**

| Option | Description | Example |
|--------|-------------|---------|
| `VARIANT=` | Select a specific software version | `test_env build VARIANT=2.375` |
| `PROFILE=` | Select a runtime profile | `test_env build PROFILE=broker-only` |
| `RPORT=` | Request a specific host port | `test_env build RPORT=8081` |

**Behavior:**
- If the requested port is unavailable, a dynamic port is allocated instead and you are notified.
- If the module does not define `VulnerableEnvironment`, the command fails with a clear error.
- If health checks fail, the container is automatically stopped and removed.
- If provisioning fails (e.g., WordPress install wizard submission), the container is torn down.

**Example output:**

```
msf exploit(...) > test_env build
[*] Resolving environment for exploit/multi/http/apache_activemq_jolokia_rce...
[*] Definition: activemq | Variant: 5.18.6 | Profile: default
[*] Image: docker.io/apache/activemq-classic:5.18.6
[*] Pulling image docker.io/apache/activemq-classic:5.18.6...
[+] Image pulled successfully.
[*] Starting container...
[+] Container started: a1b2c3d4e5f6
[*] Waiting for health check (HTTP)...
[*]   Attempt 1/12...
[*]   Attempt 2/12...
[+] Health check passed.
[+] Environment ready.
[*] Environment ID: 1
   RHOSTS       => 127.0.0.1
   RPORT        => 49152
   TARGETURI    => /
   USERNAME     => admin
   PASSWORD     => admin
[*] Suggested: exploit RHOSTS=127.0.0.1 RPORT=49152 TARGETURI=/ USERNAME=admin PASSWORD=admin
```

---

### `test_env list`

Display all tracked environments in a table.

```
msf > test_env list

Test Environments
=================

  ID  Container     Module                                          RHOST       RPORT  Status   Version
  --  ---------     ------                                          -----       -----  ------   -------
  1   a1b2c3d4e5f6  exploit/multi/http/apache_activemq_jolokia_rce  127.0.0.1   49152  running  5.18.6
  2   b2c3d4e5f6a7  exploit/unix/webapp/wp_admin_shell_upload       127.0.0.1   49153  running  latest

2 environment(s) tracked.
```

---

### `test_env modules`

Scan the framework and list all modules that declare `VulnerableEnvironment` support.

```
msf > test_env modules
[*] Scanning framework modules for test_env support...

Modules with test_env Support
=============================

  Module                                            Definition  Variant   Profile  Ports        Image
  ------                                            ----------  -------   -------  -----        -----
  exploit/multi/http/apache_activemq_jolokia_rce    activemq    5.18.6    default  8161->RPORT  docker.io/apache/activemq-classic:5.18.6
  exploit/multi/misc/apache_activemq_rce_cve_...    activemq    5.18.2    broker-  61616->RPORT docker.io/dinifarb/activemq:5.18.2
  exploit/unix/webapp/wp_admin_shell_upload         wordpress   latest    default  80->RPORT    docker.io/eystsen/vulnerablewordpress
  auxiliary/scanner/http/http_version               httpd       2.4.57    default  80->RPORT    docker.io/library/httpd:2.4.57

Found 4 module(s) with test_env support (scanned 5236 total).
```

---

### `test_env stop <ID range>`

Stop running container(s) without removing them. Accepts single IDs or ranges.

```
msf > test_env stop 1
[+] Environment 1 stopped.

msf > test_env stop 1-3,5
[+] Environment 1 stopped.
[+] Environment 2 stopped.
[+] Environment 3 stopped.
[+] Environment 5 stopped.
```

---

### `test_env start <ID>`

Restart a previously stopped environment. Re-runs readiness checks after starting.

```
msf > test_env start 1
[+] Environment 1 started. RPORT=49152
```

> **Note:** `start` accepts only a single ID for safety.

> **Provisioned environments:** For environments that required one-time provisioning during `build` (e.g., WordPress install wizard), `start` runs the `verify` check instead of the base `health_check`. This is because the container retains its filesystem state across restarts — the service is already configured, not fresh.

---

### `test_env remove <ID range>`

Tear down and remove environment(s). Stops the container if running, removes it, and purges the registry entry.

```
msf > test_env remove 1
[+] Environment 1 removed.

msf > test_env remove 1-3
[+] Environment 1 removed.
[+] Environment 2 removed.
[-] Environment 3 not found.
```

> **Safety:** If the runtime fails to remove the container, the registry entry is **preserved** so you can retry or clean up manually.

---

### `test_env remove-all`

Tear down **all** tracked environments and reset the registry.

```
msf > test_env remove-all
[*] Tearing down 3 environment(s)...
[+] All environments removed.
```

---

### `test_env exec <ID> [-z|--background]`

Execute the exploit or auxiliary module against a built environment.

**What it does:**
1. Loads the module the environment was built for
2. Applies the stored datastore options (`RHOSTS`, `RPORT`, credentials, etc.)
3. Applies the recommended payload from the environment definition (if configured)
4. Allocates fresh local ports for `SRVPORT` / `FETCH_SRVPORT` to avoid bind conflicts on repeated runs
5. Runs the module

```
msf > test_env exec 1
[*] Using exploit/multi/http/apache_activemq_jolokia_rce...
[*] Setting recommended payload for this environment: cmd/linux/http/x64/meterpreter/reverse_tcp
[*] Executing: exploit RHOSTS=127.0.0.1 RPORT=49152 TARGETURI=/ USERNAME=admin PASSWORD=admin
```

**Background execution:**

```
msf > test_env exec 1 -z
```

> **Important:** `exec` works even if you are currently `use`ing a different module. It switches context automatically.

---

### `test_env validate <ID>`

Check whether an environment's exploit produced the expected result, as defined by the environment's `ci.validation` metadata.

**For exploit modules:**
- Checks if a session was created
- Verifies session type (if specified)
- Runs a verification command and checks output

```
msf > test_env validate 1
[*] Validating environment 1 (exploit/multi/http/apache_activemq_jolokia_rce) against activemq's ci.validation...
[*] Found 2 session(s) for this module: 1, 2
[*] Using session 1 (meterpreter)
[+] PASS: environment 1 validated successfully against activemq's ci.validation.
```

**For auxiliary modules:**
- Probes the service directly
- Checks response contains expected text
- Re-verifies service health after execution

```
msf > test_env validate 4
[*] Validating environment 4 (auxiliary/scanner/http/http_version) against httpd's ci.validation...
[+] Service response contains expected text: 'Apache'
[+] PASS: environment 4 validated successfully against httpd's ci.validation.
```

> **Critical constraint:** Sessions are **process-local**. `validate` only sees sessions created in the **same** `msfconsole` process. If you ran `exec` in a different terminal window, run `validate` there too.

---

### `test_env status`

Show runtime status, managed container counts, and available environment definitions.

```
msf > test_env status
[*] Runtime: docker
[*] Managed containers: 2 total, 2 running
[*] Available definitions: activemq, httpd, openssh, wordpress
```

If a definition file has schema errors, they are reported here.

---

### `test_env help`

Display usage information for all commands.

```
msf > test_env help
Usage: test_env <command>

Commands:
  build      Build and launch environment for active module
  list       List tracked environments
  modules    List all modules with test_env support
  stop <ID>  Stop a running environment
  start <ID> Restart a stopped environment
  remove <ID> Tear down an environment
  remove-all Tear down all environments
  exec <ID>  Execute exploit against environment
  validate <ID> Check session/output against ci.validation
  status     Show runtime status
  help       Show this help
```

---

## Typical Workflows

### Workflow A: Interactive Exploit Development

```
msf > use exploit/multi/http/apache_activemq_jolokia_rce
msf exploit(...) > test_env build
[+] Environment ready. Environment ID: 1
msf exploit(...) > test_env exec 1
[*] Meterpreter session 1 opened ...
msf exploit(...) > sessions -i 1
meterpreter > shell
Process 129 created.
Channel 1 created.
id
uid=0(root) gid=0(root) groups=0(root)
exit
meterpreter > exit
msf exploit(...) > test_env remove 1
[+] Environment 1 removed.
```

### Workflow B: Multi-Version Testing

```
msf > use exploit/multi/http/apache_activemq_jolokia_rce
msf exploit(...) > test_env build VARIANT=5.18.6
[+] Environment ID: 1
msf exploit(...) > test_env build VARIANT=5.18.2 PROFILE=broker-only
[+] Environment ID: 2
msf exploit(...) > test_env list
  ID  ...  Version   Status
  --  ...  -------   ------
  1   ...  5.18.6    running
  2   ...  5.18.2    running
msf exploit(...) > test_env exec 1
msf exploit(...) > test_env exec 2
msf exploit(...) > test_env remove-all
```

### Workflow C: Auxiliary Scanner Testing

```
msf > use auxiliary/scanner/http/http_version
msf auxiliary(...) > test_env build
[+] Environment ID: 1
msf auxiliary(...) > test_env exec 1
[+] 127.0.0.1:49152 Apache/2.4.57 (Unix)
msf auxiliary(...) > test_env validate 1
[+] PASS: environment 1 validated successfully.
msf auxiliary(...) > test_env remove 1
```

### Workflow D: Resume After Restart

```
msf > load test_env
[*] TestEnv plugin loaded. Runtime: docker
[*] Successfully loaded plugin: test_env
msf > test_env list
  ID  ...  Status
  --  ...  ------
  1   ...  running
  2   ...  running
msf > test_env exec 2
```

---

## Environment Variables & Options

### Shell Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TEST_ENV_RUNTIME` | Force a specific runtime | `TEST_ENV_RUNTIME=podman msfconsole` |
| `TEST_ENV_PRESERVE` | Preserve containers on msfconsole exit | `TEST_ENV_PRESERVE=true msfconsole` |

### Metasploit Datastore Options

| Option | Description | Example |
|--------|-------------|---------|
| `TEST_ENV_RUNTIME` | Same as env var, but set inside msfconsole | `set TEST_ENV_RUNTIME podman` |
| `TEST_ENV_PRESERVE` | Same as env var, but set inside msfconsole | `set TEST_ENV_PRESERVE true` |

**Preserve behavior:**

```
msf > set TEST_ENV_PRESERVE true
TEST_ENV_PRESERVE => true
msf > unload test_env
Unloading plugin test_env...[*] TEST_ENV_PRESERVE is set. Leaving containers running.
[*] Run 'test_env remove-all' manually when done.
unloaded.
msf > load test_env
[*] TestEnv plugin loaded. Runtime: docker
[*] Successfully loaded plugin: test_env
msf > test_env list
Test Environments
=================

 ID  Container     Module               RHOST      RPORT  Status   Version
 --  ---------     ------               -----      -----  ------   -------
 1   3883fd8183da  exploit/multi/http/  127.0.0.1  49152  running  5.18.6
                   apache_activemq_jol
                   okia_rce

[*] 1 environment(s) tracked.
```
**Do Not Preserve behavior:**

```
msf > set TEST_ENV_PRESERVE false
TEST_ENV_PRESERVE => false
msf > unload test_env
Unloading plugin test_env...[*] Auto-cleaning test_env environments...
unloaded.
msf > load test_env
[*] TestEnv plugin loaded. Runtime: docker
[*] Successfully loaded plugin: test_env
msf > load test_env
[*] Auto-cleaning test_env environments...
[*] TestEnv plugin loaded. Runtime: docker
[*] Successfully loaded plugin: test_env
msf > test_env list
[*] No environments currently tracked.
```

---

## Understanding the Registry

### Where Is It Stored?

`~/.msf4/test_env_registry.yml`

This YAML file persists environment metadata across `msfconsole` restarts.

### What Is Tracked?

For each environment:
- **ID**: Monotonic local identifier (never renumbered)
- **Container ID**: Short Docker/Podman container ID
- **Module**: Full module path
- **Version**: Which variant was provisioned
- **RHOST / RPORT**: Connection details
- **Datastore**: All applied options
- **Status**: `running`, `stopped`, or `removed`
- **Allocated ports**: Host-to-container port mappings
- **Temp directories**: Cleanup targets for unnamed volumes

### Container Labels

Every container created by `test_env` carries these labels:

```
msf.vulnenv.managed_by=test_env
msf.vulnenv.instance_id=msf-hostname-12345
msf.vulnenv.module=exploit/multi/http/apache_activemq_jolokia_rce
msf.vulnenv.env_id=1
msf.vulnenv.version=5.18.6
msf.vulnenv.ports=49152:8161
```

These labels enable **state reconstruction** when `msfconsole` restarts. Even if the YAML registry is lost, `test_env` can discover running containers and rebuild the registry from labels.

---

## CI Integration

`test_env` is designed to support automated CI pipelines. A typical GitHub Actions workflow:

```yaml
name: Exploit Verification

on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start Metasploit + test_env
        run: |
          docker run -d --name msf -v $(pwd):/workspace             -e TEST_ENV_PRESERVE=true             metasploitframework/metasploit-framework:latest

      - name: Verify ActiveMQ exploit
        run: |
          docker exec msf msfconsole -q -x "
            load /workspace/test_env.rb
            use exploit/multi/http/apache_activemq_jolokia_rce
            test_env build
            test_env exec 1
            test_env validate 1
            test_env remove-all
            exit
          "
```

**Key points:**
- Environment definitions are the **single source of truth** for images, health checks, and validation expectations.
- `ci.exploit` recommends payloads that are known to work against the image.
- `ci.validation` defines what "success" means for each module.
- `exec` and `validate` must run in the **same process** (use a single `msfconsole -x` script).

---

## Troubleshooting

### Plugin fails to load

```
[-] TestEnv plugin loaded, but no container runtime found.
```

**Fix:** Install Docker or Podman and ensure the binary is in your `$PATH`.

```bash
# Docker
sudo systemctl start docker

# Podman (rootless)
podman version
```

---

### `test_env build` fails: "No active module"

```
[-] No active module. Use 'use <module>' first.
```

**Fix:** Select a module that supports `test_env`:

```
msf > use exploit/multi/http/apache_activemq_jolokia_rce
```

Or scan for supported modules:

```
msf > test_env modules
```

---

### `test_env build` fails: "Module does not define a vulnerable environment configuration"

**Fix:** The selected module has no `VulnerableEnvironment` metadata. Either:
- Use a different module
- Contribute a definition and module metadata (see Developer Documentation)

---

### Port allocation fails

```
[-] No available ports: No available ports in range 49152-65535
```

**Fix:** You have too many services bound to ephemeral ports. Run `test_env remove-all` to clean up, or manually stop orphaned containers:

```bash
docker ps -q --filter "label=msf.vulnenv.managed_by=test_env" | xargs docker stop
docker ps -aq --filter "label=msf.vulnenv.managed_by=test_env" | xargs docker rm
```

---

### Health check times out

```
[-] Health check timed out after 60 seconds
```

**Common causes:**
- The image is still downloading layers. Wait and retry.
- The service inside the container crashed. Check logs:
  ```bash
  docker logs <container_id>
  ```
- The health check endpoint is wrong. Verify the environment definition.

---

### `test_env exec` fails with "No session created"

**Causes:**
- The exploit failed. Check the module output for errors.
- `LHOST` is misconfigured. Do not hardcode `LHOST` in environment definitions.
- The target is not actually vulnerable (wrong version, patched image).

---

### `test_env validate` fails: "no session was created"

```
[-] FAIL: no session was created within 120s
```

**Causes:**
- You ran `exec` and `validate` in **different** `msfconsole` processes. Sessions are process-local.
- The exploit genuinely failed. Run `test_env exec <ID>` again and watch the output.
- The timeout is too short for slow payloads. The definition's `ci.validation.timeout` may need adjustment.

**Fix:** Run both commands in the same msfconsole:

```
msf > test_env exec 1
msf > test_env validate 1
```

---

### Podman rootless networking issues

```
[-] Rootless Podman detected but no networking backend (pasta or slirp4netns) found.
```

**Fix:** Install `pasta` or `slirp4netns`:

```bash
# Debian/Ubuntu
sudo apt install passt

# Fedora
sudo dnf install passt

# Or slirp4netns
sudo apt install slirp4netns
```

---

### `test_env remove` says "Failed to remove container" but registry entry is gone

**Actually, this won't happen.** The implementation specifically **preserves** the registry entry if `runtime.remove` fails. You can retry:

```
msf > test_env remove 1
[-] Failed to remove container for environment 1: ...
msf > test_env remove 1  # retry
[+] Environment 1 removed.
```

If the container was removed manually (outside `test_env`), run `test_env status` or reload the plugin to trigger pruning.

---

## Summary of Commands

| Command | Purpose | Args |
|---------|---------|------|
| `test_env build` | Provision environment | `[VARIANT=]` `[PROFILE=]` `[RPORT=]` |
| `test_env list` | Show tracked environments | — |
| `test_env modules` | Discover supported modules | — |
| `test_env stop` | Stop container(s) | `<ID range>` |
| `test_env start` | Restart container | `<ID>` |
| `test_env remove` | Remove environment(s) | `<ID range>` |
| `test_env remove-all` | Remove everything | — |
| `test_env exec` | Run exploit/module | `<ID>` `[-z]` |
| `test_env validate` | Verify exploit success | `<ID>` |
| `test_env status` | Show runtime + definitions | — |
| `test_env help` | Show usage | — |