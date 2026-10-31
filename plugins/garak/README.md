# Garak plugin

This plugin starts an installed Garak package, imports JSONL reports into
Metasploit, and exposes provider-independent generator and probe listings.
Install a released package in a dedicated Python environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install garak
```

Set `PYTHON` to that environment's interpreter. The integration expects Garak's
`--target_type`, `--spec`, and `--report_prefix` CLI. Scan and listing commands
require a POSIX Metasploit host. Garak inherits provider credentials from the
msfconsole environment and makes its own model connections;
Metasploit routes and proxies do not apply to those connections.

Before starting a scan or reading local garak metadata, the integration checks
that `PYTHON` can start the installed CLI. An invalid executable or missing
startup dependency produces a configuration error with the interpreter, cause,
and package installation instructions.

```text
load garak
garak_help
garak_options
garak_set PYTHON /path/to/.venv/bin/python
garak_set VERBOSE true
garak_list_generators
garak_list_probes PROBE_FILTER=test
garak_scan RHOSTS= TARGET_TYPE=test.Blank TARGET_NAME=blank PROBES=probes.test.Blank
```

The blank generator is a local smoke test. Repeat it to verify independent
reports. `garak_set OPTION VALUE` sets defaults for this loaded plugin;
`garak_unset OPTION` restores the runner default. Arguments use `OPTION=VALUE`
and override defaults for one command. Quote arguments containing spaces.
Option names are case insensitive. Matching connection/runtime values from the
active module seed each command; plugin defaults override them, and command
arguments take final precedence. Provider-specific values such as `REST_TIMEOUT`
remain explicit. The active module's datastore is not modified.
`unload garak` removes commands and defaults. Scans run in the foreground;
Ctrl-C stops the local Garak process group. Garak's internal attempt/request
parallelism still applies; each command starts one Garak process.

| Command | Purpose |
| --- | --- |
| `garak_options [scan]` | Show normal and advanced options |
| `garak_scan` | Run selected probes and import the report |
| `garak_import` | Import `REPORT_FILE` without starting Garak |
| `garak_list_generators` | List installed generator names and aliases |
| `garak_list_probes` | List installed probes, including inactive probes that Garak allows selecting explicitly |

Scanning requires explicit `TARGET_TYPE`, `TARGET_NAME`, and either `PROBES` or
a `run.spec` in `CONFIG_FILE`. Use `GENERATIONS` to choose responses per prompt
(default 1). `CONFIG_FILE` accepts
Garak's YAML or JSON provider settings. `RunTimeout` bounds local execution
(default 3600 seconds). No broad probe selection is chosen automatically.
`PROBES` accepts Garak's string spec, including family selectors and exclusions
such as `probes.packagehallucination,-probes.packagehallucination.JavaScript`.

For remote endpoints, use `RHOSTS`, `RPORT`, `SSL`, and `TARGETURI`:

```text
use auxiliary/scanner/garak/garak_ollama
set RHOSTS 192.0.2.1
set SUGGEST_PROBES false
run verbose=true
garak_scan TARGET_TYPE=ollama TARGET_NAME=example:3b PROBES=probes.test.Blank VERBOSE=true
use auxiliary/scanner/garak/garak_llama
set RHOSTS 192.0.2.2
set SUGGEST_PROBES false
run verbose=true
garak_scan TARGET_TYPE=openai.OpenAICompatible TARGET_NAME=example PROBES=probes.test.Blank CONFIG_FILE=/path/to/provider.yaml VERBOSE=true
```

The auxiliary discovery scanners work independently of `load garak`.
Their defaults are ports 11434 (Ollama) and 8080 (llama.cpp). When the discovery
module remains active, those target options carry into `garak_scan`. `TARGETURI`
is the discovery service base path;
OpenAI-compatible scans typically use `/v1/`. llama.cpp discovery accepts
`API_KEY`; scanning uses Garak credentials from its config or environment.
An unauthenticated OpenAI-compatible server still needs a placeholder API key
in Garak's config or `OPENAICOMPATIBLE_API_KEY`.

Endpoint overrides support `ollama`, `ollama.OllamaGeneratorChat`,
`ollama.OllamaGenerator`, `rest`, `rest.RestGenerator`, and
`openai.OpenAICompatible` when `CONFIG_FILE` is omitted. With a configuration,
its endpoint remains authoritative while `RHOSTS` drives host iteration and
database attribution. Leave `RHOSTS` unset for other generators and specify
their endpoint in `CONFIG_FILE`.
Discovery can run without Garak when `SUGGEST_PROBES=false`; otherwise it reads
local probe metadata. Suggestions compare input capabilities only and retain
unknown compatibility when metadata is missing.

Langflow discovery is available through `auxiliary/scanner/garak/garak_langflow`.
It reads saved flow graphs and writes REST generator configurations for supported
text flows. Generated configurations name `LANGFLOW_API_KEY` as the `key_env_var`
and contain `$KEY`, never the value. Export that variable before starting
msfconsole, or add `REST_API_KEY` to an individual scan; generated commands do
not print the secret. `REST_API_KEY` cannot be retained with `garak_set`. See the
[scanner documentation](../../documentation/modules/auxiliary/scanner/garak/garak_langflow.md)
for discovery options and execution limitations.

Each child receives private `XDG_DATA_HOME` and `XDG_CACHE_HOME` directories.
This isolates logs, reports, cached plugin metadata, and downloaded resources
between scans. Provider configuration and credentials can still be inherited
from the environment or selected explicitly with `CONFIG_FILE`.

Reports and console logs are saved as loot, including partial reports after a
timeout or failed execution. Valid evaluations print passed/failed counts.
With a connected database, imports record deduplicated `garak.run`,
`garak.evaluation`, and completed `garak.attempt` notes. Heuristic detector
failures are not reported as confirmed host vulnerabilities.

```text
garak_import REPORT_FILE=/path/to/scan.report.jsonl DB_HOST=192.0.2.1 DB_PORT=11434 VERBOSE=true
notes -t garak.run
notes -t garak.evaluation
notes -t garak.attempt
```

`DB_HOST`, `DB_PORT`, and `DB_SERVICE` set import/native-config scan attribution
only. Without them notes belong to the current workspace. Remote scans use the
actual host and port. Reports may contain prompts, responses, and configuration.

Run the plugin tests from the framework root:

```sh
bundle exec rspec spec/plugins/garak
bundle exec rubocop plugins/garak.rb plugins/garak spec/plugins/garak --format simple
```

The plugin tests cover command parsing, report import, endpoint mapping, and
local process handling. Scanner tests live in
`spec/modules/auxiliary/scanner/garak/`; shared helper tests live in
`spec/lib/msf/core/auxiliary/garak_spec.rb`.

See the scanner documentation for discovery setup and options:

- [Ollama](../../documentation/modules/auxiliary/scanner/garak/garak_ollama.md)
- [llama.cpp](../../documentation/modules/auxiliary/scanner/garak/garak_llama.md)

For REST targets, `REST_TIMEOUT=300` on `garak_scan` overrides the per-request
timeout, including when using an existing `CONFIG_FILE`. It must be positive and
requires `TARGET_TYPE=rest.RestGenerator` (or `rest`). Without the override, the
configuration or Garak default applies. `RunTimeout` limits the entire scan.

This integration supersedes the earlier auxiliary-module proposal in
[Metasploit PR #21956](https://github.com/rapid7/metasploit-framework/pull/21956).
