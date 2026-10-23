# Garak plugin

Langflow discovery is available through `auxiliary/scanner/garak/garak_langflow`.
It reads saved flow graphs and writes REST generator configurations for supported
text flows. Use its reported `TARGET_TYPE`, `TARGET_NAME`, `TARGETURI`, and
`CONFIG_FILE` with `garak_scan`. Pass `REST_API_KEY=<key>` to `garak_scan`, or export
`REST_API_KEY` before starting msfconsole;
generated files contain `$KEY`, never the API key. See the
[scanner documentation](../../documentation/modules/auxiliary/scanner/garak/garak_langflow.md)
for discovery options and execution limitations.

`REST_API_KEY` overrides the inherited REST key for that scan's child process.
It is not added to the generated configuration or process arguments. Command-line
keys may remain in msfconsole history. After updating an already loaded plugin,
run `unload garak` and `load garak` to register the new option.

This plugin ports the integration from `bwatters-r7/feature/garak-integration`
(`f68bf467734`) into msfconsole commands. The plugin and discovery scanners
share `lib/msf/core/auxiliary/garak.rb` and
`data/auxiliary/garak/probe_metadata.py`. The private execution helper reuses
Metasploit's HTTP client, scanner, option validation, loot and reporting APIs.

Install a local Garak source checkout and its Python dependencies:

```sh
git clone https://github.com/NVIDIA/garak.git
cd garak
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

Use the checkout's compatible Python version (3.11 or newer). The integration
expects Garak's `--target_type`, `--spec` and `--report_prefix` CLI. Scan and
listing commands require a POSIX Metasploit host. Garak inherits provider
credentials from the msfconsole environment and makes its own model connections;
Metasploit routes and proxies do not apply to those connections.

Before starting a scan or reading local garak metadata, the integration checks
that `PYTHON` can start the checkout's CLI. An invalid executable or missing
startup dependency produces a configuration error with the interpreter, cause,
and instructions for selecting an environment with garak dependencies installed.

```text
load garak
garak_help
garak_options
garak_set GARAK_PATH /path/to/garak
garak_set PYTHON /path/to/garak/.venv/bin/python
garak_set VERBOSE true
garak_list_generators
garak_list_probes PROBE_FILTER=test
garak_scan TARGET_TYPE=test.Blank TARGET_NAME=blank PROBES=probes.test.Blank
```

The blank generator is a local smoke test. Repeat it to verify independent
reports. `garak_set OPTION VALUE` sets defaults for this loaded plugin;
`garak_unset OPTION` restores the runner default. Arguments use `OPTION=VALUE`
and override defaults for one command. Quote arguments containing spaces.
Option names are case insensitive. The active console module is unaffected.
`unload garak` removes commands and defaults. Scans run in the foreground;
Ctrl-C stops the local Garak process group.

| Command | Purpose |
| --- | --- |
| `garak_options [scan]` | Show normal and advanced options |
| `garak_scan` | Run selected probes and import the report |
| `garak_import` | Import `REPORT_FILE` without starting Garak |
| `garak_list_generators` | List installed generator names and aliases |
| `garak_list_probes` | List probes, optionally narrowed with `PROBE_FILTER` |

Scanning requires explicit `TARGET_TYPE`, `TARGET_NAME`, and `PROBES`. Use
`GENERATIONS` to choose responses per prompt (default 1). `CONFIG_FILE` accepts
Garak's YAML or JSON provider settings. `RunTimeout` bounds local execution
(default 3600 seconds). No broad probe selection is chosen automatically.

For remote endpoints, use `RHOSTS`, `RPORT`, `SSL`, and `TARGETURI`:

```text
use auxiliary/scanner/garak/garak_ollama
set RHOSTS 192.0.2.1
set SUGGEST_PROBES false
run verbose=true
garak_scan RHOSTS=192.0.2.1 RPORT=11434 TARGET_TYPE=ollama TARGET_NAME=example:3b PROBES=probes.test.Blank VERBOSE=true
use auxiliary/scanner/garak/garak_llama
set RHOSTS 192.0.2.2
set SUGGEST_PROBES false
run verbose=true
garak_scan RHOSTS=192.0.2.2 RPORT=8080 TARGETURI=/v1/ TARGET_TYPE=openai.OpenAICompatible TARGET_NAME=example PROBES=probes.test.Blank CONFIG_FILE=/path/to/provider.yaml VERBOSE=true
```

The auxiliary discovery scanners work independently of `load garak`.
Their defaults are ports 11434 (Ollama) and 8080 (llama.cpp); scans default to
80. Set the scan port explicitly. `TARGETURI` is the discovery service base path;
OpenAI-compatible scans typically use `/v1/`. llama.cpp discovery accepts
`API_KEY`; scanning uses Garak credentials from its config or environment.
An unauthenticated OpenAI-compatible server still needs a placeholder API key
in Garak's config or `OPENAICOMPATIBLE_API_KEY`.

Endpoint overrides support `ollama`, `ollama.OllamaGeneratorChat`,
`ollama.OllamaGenerator`, `rest`, `rest.RestGenerator`, and
`openai.OpenAICompatible`. They retain other generator configuration. Leave
`RHOSTS` unset for other generators and specify their endpoint in `CONFIG_FILE`.
Discovery can run without Garak when `SUGGEST_PROBES=false`; otherwise it reads
local probe metadata. Suggestions compare input capabilities only and retain
unknown compatibility when metadata is missing.

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
bundle exec rspec --options /dev/null plugins/garak/spec
bundle exec rubocop plugins/garak.rb plugins/garak --format simple
```

The plugin tests run without PostgreSQL and cover command parsing, report
import, endpoint mapping, and local process handling. Scanner tests live in
`spec/modules/auxiliary/scanner/garak/`; shared helper tests live in
`spec/lib/msf/core/auxiliary/garak_spec.rb`.

See the scanner documentation for discovery setup and options:

- [Ollama](../../documentation/modules/auxiliary/scanner/garak/garak_ollama.md)
- [llama.cpp](../../documentation/modules/auxiliary/scanner/garak/garak_llama.md)

For REST targets, `REST_TIMEOUT=300` on `garak_scan` overrides the per-request
timeout, including when using an existing `CONFIG_FILE`. It must be positive and
requires `TARGET_TYPE=rest.RestGenerator` (or `rest`). Without the override, the
configuration or Garak default applies. `RunTimeout` limits the entire scan.
