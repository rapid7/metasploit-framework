## Vulnerable Application

This scanner identifies Langflow, reads flow graphs, and reports the values needed
to target a saved flow with the Garak plugin. It saves a JSON `CONFIG_FILE` for
each flow with exactly one recognized text input and one selected text output.
Recognized components are `ChatInput`, `TextInput`, `ChatOutput`, and `TextOutput`.
Other component types (including `CSVAgent`) are listed as context, without
reporting vulnerabilities. Custom inputs, multiple inputs, and missing outputs
require manual configuration.

Discovery uses GET requests only. It does not build, create, modify, or run flows.
Saved files and database notes contain selected metadata, not raw graphs or keys.
The generated configurations target the Langflow application, rather than its
underlying model provider. Generation behavior, graph connectivity, provider
credentials, tools, file dependencies, and response extraction remain unverified.

### Setup

No vulnerability is required. Use an authorized Langflow instance with a saved
flow. For example, start a local container:

```sh
docker run -d --name garak-langflow -p 127.0.0.1:7860:7860 \
  -e LANGFLOW_AUTO_LOGIN=true langflowai/langflow:1.10.0
docker exec garak-langflow langflow api-key
```

Open the UI, create a Basic Prompting flow with Chat Input and Chat Output, configure
its model provider, and save it. Use the API key printed by the CLI for discovery.
Automatic login is suitable only for an isolated lab; do not expose this container
to untrusted networks.

## Verification Steps

1. Start msfconsole.
2. `use auxiliary/scanner/garak/garak_langflow`
3. `set RHOSTS 127.0.0.1`
4. `set RPORT 7860`
5. `set API_KEY <existing-langflow-api-key>` if discovery requires authentication.
6. `run VERBOSE=true`
7. Confirm the flow ID, component types, run endpoint, and saved configuration path.
8. Inspect the saved JSON before running Garak. Discovery alone does not prove the flow works.

Generated configurations set `key_env_var` to `LANGFLOW_API_KEY` and substitute
that environment value for `$KEY` in the `x-api-key` header. Export the key before
starting msfconsole so both plugin and terminal commands inherit it. Alternatively,
append `REST_API_KEY=<key>` to a suggested plugin command; the value is supplied
only to its child process, but remains visible in console history. Discovery never
prints or saves the key. Authentication can be required for a flow run even when
anonymous discovery succeeds.

`RunTimeout` defaults to one hour for the complete scan. Probe families can expand
to many active probes, so use `garak_list_probes` (or Garak's `--list_probes -S`
option) to review a selection and increase the timeout for large suites.

```text
load garak
garak_set PYTHON /path/to/.venv/bin/python
garak_scan TARGET_TYPE=rest.RestGenerator TARGET_NAME=http://127.0.0.1:7860/api/v1/run/<flow-id> CONFIG_FILE=/path/to/saved/config.json PROBES=probes.test.Blank REST_API_KEY_ENV=LANGFLOW_API_KEY VERBOSE=true
```

Use the exact discovered values, including the base path. The REST generator uses
the URL as its target name. When `CONFIG_FILE` is omitted, the plugin maps `RHOSTS`,
`RPORT`, `SSL`, and `TARGETURI` to its `uri`. In a generated configuration its
`uri` remains authoritative, while the active module's connection settings are
used to associate imported database results. Garak makes its own connections;
Metasploit routes and HTTP client settings do not automatically apply. Garak
executes the selected flow, which can call external providers and tools. The
template omits `session_id` so Langflow can assign a fresh session for each request.

## Options

### SUGGEST_PROBES

Defaults to `true`. After discovering a flow with a usable REST configuration,
lists active probes from the local Garak installation. This list does not
establish compatibility with the flow or its underlying model. Set to `false`
to discover flows without a local Garak runtime.

### PROBE_FILTER

Optional case-insensitive substring to narrow the active probe list, such as
`dan` or `encoding`. If no active probes match, change or unset the filter.

### PYTHON

Python executable with the Garak package installed, used to list probes.
Defaults to `python3`.


### OUTPUT_YAML

Set `OUTPUT_YAML true` to save a Garak YAML configuration in Metasploit loot for
each supported discovered target. The scanner prints the saved path for
`CONFIG_FILE`. The file includes `plugins.target_type`, `plugins.target_name`,
and provider settings, so it can also be used with `python -m garak --config <path>`.
Defaults to `false`. No local Garak installation is needed to write YAML; disable
`SUGGEST_PROBES` to discover without local Garak.

With `SUGGEST_PROBES true`, the YAML includes active probe selections under
`run.spec.include`, narrowed by `PROBE_FILTER`. Both the terminal and suggested
plugin commands leave that complete YAML spec in control. This also preserves
manually added `run.spec.exclude` selections. A filter with no matches writes
`probes.none` rather than selecting all probes. With `SUGGEST_PROBES false`, no
probe selection is written and the suggested command uses `probes.test.Blank`.

When enabled, YAML replaces the default JSON flow configuration. The REST request
template and `$KEY` authentication placeholder are retained.


### API_KEY

Optional existing Langflow API key sent in `x-api-key` for discovery. It is never
written to the generated configuration or database notes.

### FLOW_ID

Optional flow UUID. Reads that flow directly instead of listing the inventory.
Useful when list access is restricted or the list response format is unsupported.

### INCLUDE_EXAMPLES

Advanced option, default `false`. Includes example flows in the inventory. Example
flows often need provider configuration or files before they can run.

### REST_TIMEOUT

Advanced option, default `300` seconds. Saves `request_timeout` in the Garak REST
generator configuration. Increase it for slow flows. For existing configurations,
pass `REST_TIMEOUT=300` to `garak_scan` to override their request timeout. This is
separate from `RunTimeout`, which limits the entire Garak process, and from
`HttpClientTimeout`, which applies to Metasploit discovery requests.

### OUTPUT_COMPONENT

Advanced option. Exact component ID to select when a flow has multiple text outputs.
An ID that is not a recognized text output prevents configuration generation.
Multiple text inputs still require manual configuration.

## Scenarios

### Langflow 1.10.0 on Docker

```msf
msf > use auxiliary/scanner/garak/garak_langflow
msf auxiliary(scanner/garak/garak_langflow) > set RHOSTS 10.5.134.138
RHOSTS => 10.5.134.138
msf auxiliary(scanner/garak/garak_langflow) > set API_KEY [redacted]
API_KEY => [redacted]
msf auxiliary(scanner/garak/garak_langflow) > set FLOW_ID 776f41d8-1649-4a78-a60e-c52edca467ea
FLOW_ID => 776f41d8-1649-4a78-a60e-c52edca467ea
msf auxiliary(scanner/garak/garak_langflow) > set PYTHON /tmp/msf-garak-live-venv/bin/python
PYTHON => /tmp/msf-garak-live-venv/bin/python
msf auxiliary(scanner/garak/garak_langflow) > set PROBE_FILTER test.
PROBE_FILTER => test.
msf auxiliary(scanner/garak/garak_langflow) > set OUTPUT_YAML true
OUTPUT_YAML => true
msf auxiliary(scanner/garak/garak_langflow) > run verbose=true
[+] Langflow 1.10.0 detected
[*] Candidate target types (generation support has not been tested)
===============================================================

  TARGET_TYPE
  -----------
  rest.RestGenerator

[+] Garak YAML configuration saved: /home/tmoose/.msf4/loot/20261026153323_default_10.5.134.138_langflow.garak.c_602925.yaml
[*] Use garak_scan TARGET_TYPE=rest.RestGenerator TARGET_NAME=http://10.5.134.138:7860/api/v1/run/776f41d8-1649-4a78-a60e-c52edca467ea CONFIG_FILE=/home/tmoose/.msf4/loot/20261026153323_default_10.5.134.138_langflow.garak.c_602925.yaml PYTHON=/tmp/msf-garak-live-venv/bin/python REST_API_KEY_ENV=LANGFLOW_API_KEY VERBOSE=true
[*] Or run in a terminal: /tmp/msf-garak-live-venv/bin/python -m garak --config /home/tmoose/.msf4/loot/20261026153323_default_10.5.134.138_langflow.garak.c_602925.yaml
[*] Garak values: TARGET_TYPE=rest.RestGenerator TARGET_NAME=http://10.5.134.138:7860/api/v1/run/776f41d8-1649-4a78-a60e-c52edca467ea CONFIG_FILE=/home/tmoose/.msf4/loot/20261026153323_default_10.5.134.138_langflow.garak.c_602925.yaml
[*] Candidate target names (generation support has not been tested)
===============================================================

  TARGET_NAME                                                               Flow ID                               Name
  -----------                                                               -------                               ----
  http://10.5.134.138:7860/api/v1/run/776f41d8-1649-4a78-a60e-c52edca467ea  776f41d8-1649-4a78-a60e-c52edca467ea  Garak Documentation Basic Prompting

[*] Langflow candidate targets (generation has not been tested)
===========================================================

  Flow ID                               Name                                 Components                                                   Configuration
  -------                               ----                                 ----------                                                   -------------
  776f41d8-1649-4a78-a60e-c52edca467ea  Garak Documentation Basic Prompting  ChatInput, ChatOutput, LanguageModelComponent, Prompt, note  /home/tmoose/.msf4/loot/20261026153323_default_10.5.134.138_langflow.garak.c_602925.yaml

[*] API_KEY is used only for discovery; set LANGFLOW_API_KEY before starting msfconsole, or pass REST_API_KEY explicitly, if flow execution requires authentication
[*] Run garak_scan while this module is active to inherit RHOSTS, RPORT and SSL; flow execution and response extraction remain unverified
[+] Available PROBES selections from the local garak installation:
[*] Probe: probes.test.Blank
[*] Probe: probes.test.Test
[*] Use garak_scan with PROBES set to a probe, a family, or comma-separated selections
[*] Available probes are not verified for these flows; validate input compatibility and dependencies before scanning
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
