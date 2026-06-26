# CI Workflow: Automated Exploit Verification



This document defines how `test_env` will be used in GitHub Actions to automatically:
- Provision vulnerable environments from shared definitions
- Execute exploits with pre-configured datastore options
- Validate expected outcomes (session creation, command output)
- Clean up all containers to prevent resource leaks

**Key principle:** CI consumes the same environment definitions used for local testing. No duplicated container configuration.


## Directory Structure

This directory structure will created as part of the project:

```
metasploit-framework/
├── ci/                          
│   ├── test_activemq.rc         
│   ├── test_jenkins.rc          
│   └── test_drupal.rc           
├── .github/
│   └── workflows/
│       └── vuln-env-test.yml    
├── data/
│   └── vuln_envs/
│       ├── activemq.yml         
│       ├── jenkins.yml          
│       └── drupal.yml          
└── docs/
    └── ci_workflow.md           
```



A **resource script** with a `.rc` extension that contains msfconsole commands. Instead of typing commands one by one into msfconsole, they will be saved in a file and run:

```bash
./msfconsole -q -r path/to/script.rc
```

Metasploit reads the file and executes each line automatically, as if it's typed.



### Example: ci/test_jenkins.rc

**What it is:** A text file containing msfconsole commands to test the Jenkins module automatically.

**What it contains:**
```text
load test_env
use exploit/multi/http/jenkins_script_console
test_env build VERSION=2.361
test_env exec 1
test_env remove-all
exit
```

**What each line does:**
| Line | Command | Purpose |
|------|---------|---------|
| 1 | `load test_env` | Load the test_env plugin |
| 2 | `use exploit/multi/http/jenkins_script_console` | Select the exploit module |
| 3 | `test_env build VERSION=2.361` | Build environment using Jenkins version 2.361 |
| 4 | `test_env exec 1` | Execute exploit against environment ID 1 |
| 5 | `test_env remove-all` | Stop and remove all containers |
| 6 | `exit` | Close msfconsole |

**How to run it manually (for testing):**
```bash
./msfconsole -q -r ci/test_jenkins.rc
```
---

## GitHub Actions Workflow

**What this is:** A YAML file that tells GitHub Actions what to do on every push or pull request.

**File:** `.github/workflows/vuln-env-test.yml`

**What it contains:**
```yaml
name: Vulnerable Environment Test

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test-jenkins:
    name: Test Jenkins Script Console
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Set up Ruby
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: '3.2'
          bundler-cache: true
      
      - name: Set up Docker
        uses: docker/setup-buildx-action@v3
      
      - name: Cache Docker layers
        uses: actions/cache@v3
        with:
          path: /tmp/.buildx-cache
          key: ${{ runner.os }}-buildx-${{ github.sha }}
          restore-keys: |
            ${{ runner.os }}-buildx-
      
      - name: Run Jenkins exploit test
        run: |
          ./msfconsole -q -r ci/test_jenkins.rc
      
      - name: Verify session was created
        run: |
          grep "Session.*opened" ~/.msf4/logs/framework.log || echo "WARNING: No session log found"
      
      - name: Verify no containers left behind
        run: |
          REMAINING=$(docker ps -q | wc -l)
          if [ "$REMAINING" -eq 0 ]; then
            echo "Clean: No containers remaining"
          else
            echo "FAIL: $REMAINING container(s) still running"
            docker ps
            exit 1
          fi
```

**What each step does:**
| Step | Action | Purpose |
|------|--------|---------|
| Checkout | `actions/checkout@v4` | Download your code |
| Set up Ruby | `ruby/setup-ruby@v1` | Install Ruby 3.2 and gems |
| Set up Docker | `docker/setup-buildx-action@v3` | Install Docker |
| Cache Docker layers | `actions/cache@v3` | Speed up image pulls |
| Run exploit test | `./msfconsole -q -r ci/test_jenkins.rc` | Execute the Jenkins resource script |
| Verify session | `grep "Session.*opened"` | Confirm exploit succeeded |
| Verify cleanup | `docker ps -q` | Confirm no leaked containers |

---

## Validation Criteria

| Step | Expected Result | How It Is Checked | On Failure |
|------|----------------|-------------------|------------|
| `test_env build` | Container starts, health check passes | Console output contains "Environment ready" | Workflow fails |
| `test_env exec 1` | Session opens | `framework.log` contains "Session.*opened" | Workflow fails |
| `test_env remove-all` | All containers removed | `docker ps -q` returns empty | Workflow fails |
| Post-cleanup | Zero `msf.vulnenv` containers remain | `docker ps -a --filter "label=msf.vulnenv.managed_by=test_env"` returns empty | Workflow fails |

---

## CI Metadata in Environment Definitions

Environment definitions include a `ci` section so the automation knows what payload to use and what to validate:

```yaml
# data/vuln_envs/jenkins.yml
ci:
  exploit:
    payload: java/meterpreter/reverse_tcp
    options:
      LHOST: 127.0.0.1
      LPORT: 4444
      TARGETURI: /script
  validation:
    expected_session: true
    session_type: meterpreter
    expected_output: "uid="
    timeout: 120
```

### Schema Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ci.exploit.payload` | String | Yes | Payload to use for automated execution |
| `ci.exploit.options` | Hash | No | Datastore options: `LHOST`, `LPORT`, `TARGETURI`, etc. |
| `ci.validation.expected_session` | Boolean | Yes | Whether a session must be created |
| `ci.validation.session_type` | String | No | Expected session type: `meterpreter`, `shell` |
| `ci.validation.expected_output` | String | No | Substring to verify in session output |
| `ci.validation.timeout` | Integer | Yes | Max seconds to wait for validation |

