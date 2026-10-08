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
docker run --name garak-langflow -p 127.0.0.1:7860:7860 langflowai/langflow:1.10.0
```

Open the UI, create a Basic Prompting flow with Chat Input and Chat Output, configure
its model provider, and save it. Obtain an existing API key from Langflow's settings.
Do not expose the lab container to untrusted networks.

## Verification Steps

1. Start msfconsole.
2. `use auxiliary/scanner/garak/garak_langflow`
3. `set RHOSTS 127.0.0.1`
4. `set RPORT 7860`
5. `set API_KEY <existing-langflow-api-key>` if discovery requires authentication.
6. `run VERBOSE=true`
7. Confirm the flow ID, component types, run endpoint, and saved configuration path.
8. Inspect the saved JSON before running Garak. Discovery alone does not prove the flow works.

When `API_KEY` is supplied, the suggested `garak_scan` command includes it as
`REST_API_KEY`, along with the interpreter, configuration, and connectivity probe.
The key is printed in the command but is not stored in configuration loot or notes.
Without a discovery key, add `REST_API_KEY=<key>` to the command if needed. Garak
substitutes this environment variable for `$KEY` in the generated `x-api-key` header.
An API key can be required to run a flow even if anonymous discovery succeeds.
The suggested standalone terminal command supplies the same key through its environment.

The suggested `garak_scan` command includes `RunTimeout` with 300 seconds per
listed probe (300 seconds for the single connectivity probe). Duplicate names and
family selectors already represented by individual probes are not counted again.
This is a total scan budget, not a timeout for each prompt. Probes containing many
prompts can exceed this budget; increase the command's `RunTimeout` when needed.

```text
load garak
garak_set GARAK_PATH /path/to/garak
garak_set PYTHON /path/to/garak/.venv/bin/python
garak_scan TARGET_TYPE=rest.RestGenerator TARGET_NAME=http://127.0.0.1:7860/api/v1/run/<flow-id> RHOSTS=127.0.0.1 RPORT=7860 SSL=false TARGETURI=/api/v1/run/<flow-id> CONFIG_FILE=/path/to/saved/config.json PROBES=probes.test.Blank VERBOSE=true
```

Use the exact discovered values, including the base path. The REST generator uses
the URL as its target name; the plugin maps `RHOSTS`, `RPORT`, `SSL`, and `TARGETURI`
to its `uri`. For a virtual host, unset `RHOSTS` in the plugin and retain the URI in
the saved configuration. Garak makes its own connections; Metasploit routes and
HTTP client settings do not automatically apply. Garak executes the selected flow,
which can call external providers and tools. The template omits `session_id` so
Langflow can assign a fresh session for each request.

## Options

### SUGGEST_PROBES

Defaults to `true`. After discovering a flow with a usable REST configuration,
lists available probes from the local Garak installation. This list does not
establish compatibility with the flow or its underlying model. Set to `false`
to discover flows without a local Garak runtime.

### PROBE_FILTER

Optional case-insensitive substring to narrow the available probe list, such
as `dan` or `encoding`. If no probes match, change or unset the filter.

### GARAK_PATH

Local Garak source checkout used to list probes. Defaults to the `garak`
directory beside the Metasploit checkout. Only used when `SUGGEST_PROBES` is enabled.

### PYTHON

Python executable with the Garak checkout dependencies installed, used to list
probes. Defaults to `python3`.


### OUTPUT_YAML

Set `OUTPUT_YAML true` to save a Garak YAML configuration in Metasploit loot for
each supported discovered target. The scanner prints the saved path for
`CONFIG_FILE`. The file includes `plugins.target_type`, `plugins.target_name`,
and provider settings, so it can also be used with `python -m garak --config <path>`.
Defaults to `false`. No local Garak installation is needed to write YAML; disable
`SUGGEST_PROBES` to discover without local Garak.

With `SUGGEST_PROBES true`, the YAML includes the listed probe selections under
`run.spec.include`, narrowed by `PROBE_FILTER`. Running `python -m garak --config`
uses these selections; the suggested `garak_scan` command supplies the same values.
A filter with no matches writes `probes.none` rather than selecting all probes.
With `SUGGEST_PROBES false`, no probe selection is written.

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

Human-verified console scenarios are pending.
