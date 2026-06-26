# test_env User Workflow (Design Specification)

This document specifies the intended user interaction with `test_env`. Every transcript below is the **target behavior** that implementation must achieve. These are our acceptance criteria.

---

## Scenario 1: Build an Environment for the Active Module

**Precondition:** The user has selected a module that defines a `VulnEnv` key in its metadata.

**Input:**
```
msf > use exploit/multi/http/apache_activemq_jolokia_rce
msf exploit(apache_activemq_jolokia_rce) > test_env build
```

**Expected behavior:**
- The plugin detects the active module and reads `mod.info['VulnEnv']`
- It resolves the definition name (`activemq`) and loads `data/vuln_envs/activemq.yml`
- It selects the default version (`5.18.6`)
- It auto-detects the container runtime (Docker preferred, Podman fallback)
- It pulls `apache/activemq-classic:5.18.6` if not already cached
- It starts the container with localhost binding and dynamic port allocation
- It waits for the health check defined in the YAML (`GET /api/jolokia/` → 200)
- Once ready, it prints the mapped host port and suggests datastore settings

**Expected output:**
```
[*] Resolving environment for apache_activemq_jolokia_rce...
[*] Definition: activemq | Version: 5.18.6 | Runtime: docker
[*] Pulling image apache/activemq-classic:5.18.6...
[*] Starting container...
[*] Waiting for health check (GET /api/jolokia/)...
[+] Environment ready.
[*]    RHOSTS    => 127.0.0.1
[*]    RPORT     => 49152
[*]    TARGETURI => /api/jolokia/
[*]    USERNAME  => admin
[*]    PASSWORD  => admin
[*] Suggested: set RHOSTS 127.0.0.1; set RPORT 49152; exploit
```

**Postcondition:** A container is running. The module's datastore options (`RHOSTS`, `RPORT`, etc.) are automatically populated. The environment is registered in the in-memory registry with a unique ID.

---

## Scenario 2: Build with a Specific Version

**Input:**
```
msf exploit(multi/http/jenkins_script_console) > test_env build VERSION=2.375
```

**Expected behavior:**
- The `VERSION=2.375` argument overrides the `default_version` from the module's `VulnEnv`
- The plugin loads `jenkins.yml` and selects the `2.375` entry under `versions`
- If the version does not exist, the command fails immediately with a list of available versions

**Expected output (success):**
```
[*] Selected version: 2.375
[*] Pulling image vulnhub/jenkins:2.375...
[*] Starting container...
[*] Waiting for health check (GET /login)...
[+] Environment ready.
[*]    RHOSTS    => 127.0.0.1
[*]    RPORT     => 49153
[*]    TARGETURI => /script
[*] Suggested: set RHOSTS 127.0.0.1; set RPORT 49153; exploit
```

**Expected output (failure — version not found):**
```
[-] Version '9.99' not defined for 'jenkins'. Available: 2.361, 2.375
```

---

## Scenario 3: Request a Specific Port (with Automatic Fallback)

**Input:**
```
msf exploit(multi/http/jenkins_script_console) > test_env build RPORT=8080
```

**Expected behavior:**
- The plugin attempts to bind host port 8080 to the container's exposed port
- If 8080 is already in use on the host, the `PortAllocator` scans the ephemeral range (49152–65535) for an available port
- The user is informed of the fallback. The allocated port is stored in the registry.

**Expected output:**
```
[*] Requested port 8080 is unavailable. Using dynamically allocated port 49154.
[*] Starting container...
[*] Waiting for health check (GET /login)...
[+] Environment ready.
[*]    RHOSTS    => 127.0.0.1
[*]    RPORT     => 49154
[*]    TARGETURI => /script
```

---

## Scenario 4: List Active Environments

**Input:**
```
msf exploit(multi/http/jenkins_script_console) > test_env list
```

**Expected behavior:**
- The plugin queries the in-memory registry and prints a table using `Rex::Ui::Text::Table`
- Each row shows: ID, container ID (truncated), module fullname, RHOST, RPORT, status, version
- The table is sorted by ID

**Expected output:**
```
Environments
============

ID  Container     Module                                     RHOST       RPORT  Status   Version
--  ---------     ------                                     -----       -----  ------   -------
1   4f3a2b1c...   exploit/multi/http/jenkins_script_console  127.0.0.1   49153  running  2.375
2   9e8d7c6b...   exploit/multi/http/apache_activemq_jolokia   127.0.0.1   49152  running  5.18.6
```

---

## Scenario 5: Execute the Stored Exploit

**Input:**
```
msf exploit(multi/http/jenkins_script_console) > test_env exec 1
```

**Expected behavior:**
- The plugin looks up environment ID 1 in the registry
- It verifies the container is running via `docker inspect` or `podman inspect`
- It automatically sets the module's datastore options (`RHOSTS`, `RPORT`, `TARGETURI`, etc.) from the registry record
- It invokes the module's `exploit` method (or `run_simple`) with these options
- If the environment is stopped, it prints an error telling the user to start it first

**Expected output (success):**
```
[*] Executing exploit against environment 1...
[*] Set RHOSTS 127.0.0.1
[*] Set RPORT 49153
[*] Set TARGETURI /script
[*] Started reverse TCP handler on 127.0.0.1:4444
[+] Session 1 opened (127.0.0.1:4444 -> 127.0.0.1:49153)
```

**Expected output (failure — environment stopped):**
```
[-] Environment 1 is not running. Start it with: test_env start 1
```

---

## Scenario 6: Stop and Restart an Environment

**Input:**
```
msf exploit(multi/http/jenkins_script_console) > test_env stop 1
```

**Expected behavior:**
- The plugin calls `docker stop` (or `podman stop`) on the container ID stored in the registry
- It updates the registry status to `stopped`
- It preserves the registry record so the environment can be restarted

**Expected output:**
```
[*] Stopping container 4f3a2b1c...
[+] Environment 1 stopped.
```

**Input (restart):**
```
msf exploit(multi/http/jenkins_script_console) > test_env start 1
```

**Expected behavior:**
- The plugin calls `docker start` on the container
- It re-runs the health check defined in the environment definition
- It updates the registry status to `running`

**Expected output:**
```
[*] Starting container 4f3a2b1c...
[*] Waiting for health check...
[+] Environment 1 running. RPORT=49153
```

---

## Scenario 7: Remove a Single Environment

**Input:**
```
msf exploit(multi/http/jenkins_script_console) > test_env remove 1
```

**Expected behavior:**
- The plugin stops the container if it is running
- It calls `docker rm` (or `podman rm`) to remove the container
- It removes the record from the in-memory registry
- If the database is active (Phase 2), it updates the DB status to `removed`

**Expected output:**
```
[*] Stopping container 4f3a2b1c...
[*] Removing container 4f3a2b1c...
[+] Environment 1 removed.
```

---

## Scenario 8: Remove All Environments

**Input:**
```
msf exploit(multi/http/jenkins_script_console) > test_env remove-all
```

**Expected behavior:**
- The plugin iterates all entries in the registry
- For each, it stops and removes the container
- It clears the in-memory registry
- If any container fails to stop/remove, it prints a warning but continues

**Expected output:**
```
[*] Tearing down 2 environment(s)...
[*] Stopping container 4f3a2b1c...
[*] Removing container 4f3a2b1c...
[*] Stopping container 9e8d7c6b...
[*] Removing container 9e8d7c6b...
[+] All environments removed.
```

---

## Quick Reference: Command Summary

| Command | Arguments | Description |
|---------|-----------|-------------|
| `test_env build` | `[VERSION=x]` `[RPORT=y]` | Build and launch environment for active module |
| `test_env list` | none | Show all tracked environments |
| `test_env exec` | `<ID>` | Execute exploit against environment `<ID>` |
| `test_env stop` | `<ID>` | Stop a running environment |
| `test_env start` | `<ID>` | Restart a stopped environment |
| `test_env remove` | `<ID>` | Tear down and remove one environment |
| `test_env remove-all` | none | Tear down all environments |
| `test_env help` | none | Show usage information |

---

## Error Handling Specification

| Error Condition | Expected Output | Implementation Notes |
|-----------------|----------------|---------------------|
| No active module | `[-] No active module. Use 'use <module>' first.` | Check `driver.active_module` before any other logic |
| Module has no `VulnEnv` | `[-] Module does not define a vulnerable environment configuration.` | Check `mod.info['VulnEnv']` after resolving active module |
| No container runtime | `[-] No container runtime found. Install Docker or Podman.` | `RuntimeAdapter.detect` returns `nil` |
| Image pull fails | `[-] Failed to pull image: <image>` | Check exit status of `docker pull` |
| Container start fails | `[-] Failed to start container: <error>` | Catch `RuntimeAdapter#run` exceptions |
| No available ports | `[-] No available ports in range 49152-65535` | `PortAllocator` raises after exhausting range |
| Health check timeout | `[-] Health check timed out after <N> seconds` | `HealthManager` exceeds `retries * interval` |
| Environment ID not found | `[-] Environment <ID> not found` | Registry lookup returns `nil` |
| Environment not running | `[-] Environment <ID> is not running. Start it with: test_env start <ID>` | Check `status` field before `exec` |

---

## Notes for Implementers

- All output prefixes (`[*]`, `[+]`, `[-]`) must use `print_status`, `print_good`, `print_error` respectively
- Table output must use `Rex::Ui::Text::Table` for consistency with built-in commands like `sessions`, `jobs`
- The `test_env` command must be available regardless of whether a database is connected (Phase 1 is in-memory only)
- Container labels must be applied on every `run` so that orphaned containers can be identified even if the registry is lost
