## Vulnerable Application

This module identifies Ollama services and provides garak target configuration.
It requires the `Ollama is running` banner at the base path, then queries
[`GET /api/tags`](https://docs.ollama.com/api/tags) for installed model names.
No vulnerability is required. By default, the scanner queries each model with
`POST /api/show` and compares its capabilities with local garak probe and adapter
metadata. This requires a Python environment with the garak package installed.
Set `SUGGEST_PROBES false` for target discovery without
garak. The module does not generate text, execute probes, or download models.

Start a local test instance with Docker:

```sh
docker run -d --name garak-ollama -p 127.0.0.1:11434:11434 ollama/ollama
docker exec garak-ollama ollama pull qwen2.5:3b
```

Output includes candidate `TARGET_TYPE` values `ollama.OllamaGeneratorChat`
(chat), `ollama.OllamaGenerator` (completion), and `ollama` (chat alias).
Full installed model names, including tags, are listed as `TARGET_NAME` values.
Target types and names are displayed in tables, matching the suggested-probe table format.
Discovery does not verify generation support for individual models or select one
automatically. Compatible services can imitate the banner; proxies that hide it
will not be identified.

With a database connected, the scanner records the HTTP/HTTPS service and an
`ollama.garak.targets` note containing the base path, adapter candidates and
model names. Identical notes are deduplicated. No vulnerabilities are reported.

Probe suggestions require every declared input type to be supported by both the
model and the adapter. Ollama `completion` maps to text input and `vision` maps
to image input. Models that only declare embedding support are not recommended
for generation probes. Unrecognized capabilities or missing metadata retain an
unknown classification rather than implying compatibility. Adapter metadata can
exclude image probes even when a model supports images.

The console lists suggested probe names and their matching adapters. A JSON loot
file and an `ollama.garak.probes` database note retain the model capabilities,
identified inputs and each considered probe's status for each
adapter: `suggested`, `incompatible`, or `unknown`. Unknown model capabilities
produce no suggestions. Failure to retrieve `/api/show` does not discard the
already discovered model names.

These are input-type suggestions, not proof of compatibility or vulnerability.
They include active and inactive probes present in garak's metadata. Language,
credentials, dependencies, resource use and behavioral prerequisites still need
review before running them. Metadata is obtained from garak's plugin cache; no
probes or generators are instantiated by the metadata query.

## Verification Steps

1. Start an Ollama instance and install a model.
1. Start `msfconsole`.
1. Do: `use auxiliary/scanner/garak/garak_ollama`.
1. Do: `set RHOSTS 127.0.0.1`.
1. Set `PYTHON` to an interpreter with the garak package installed.
1. Do: `run verbose=true`.
1. Confirm that `TARGET_TYPE` candidates, installed `TARGET_NAME` values and
   capability-based probe suggestions appear.
1. Use these values with the `garak_scan` command after `load garak`. Run it while
   this module is active to inherit `RHOSTS`, `RPORT`, `SSL`, and `TARGETURI`.
   Select `PROBES` separately.

The default port is `11434`. For a reverse proxy mounted at `/ollama/`, set
`TARGETURI` to `/ollama/`; the model query uses `/ollama/api/tags`.
Use the HTTP client's SSL, authentication, proxy and timeout options as needed.
Authentication for garak itself must be configured separately.

## Options

### OUTPUT_YAML

Set `OUTPUT_YAML true` to save a Garak YAML configuration in Metasploit loot for
each supported discovered target. The scanner prints the saved path for
`CONFIG_FILE`. The file includes `plugins.target_type`, `plugins.target_name`,
and provider settings, so it can also be used with `python -m garak --config <path>`.
Defaults to `false`. No local Garak installation is needed to write YAML; disable
`SUGGEST_PROBES` in Ollama and llama.cpp scanners to discover without local Garak.

The configuration selects `ollama.OllamaGeneratorChat`. For authenticated services,
export `OLLAMA_API_KEY` before launching Garak.


### SUGGEST_PROBES

Defaults to `true`. Query model capabilities and compare against local garak
metadata. Set to `false` to discover only target types and names without garak.
There is no LIST_PROBES action; suggestions are part of the scan.

### PYTHON

Python executable with the garak package installed, default `python3`.
For example, a pipx installation may use
`/home/tmoose/.local/share/pipx/venvs/garak/bin/python`.

### PROBE_FILTER

Optional case-insensitive substring applied to probe names before displaying and
saving the compatibility results. Set to `dan` to consider DAN probes. Unset to
consider every probe present in local garak metadata.

### RunTimeout

Advanced option limiting the local metadata process runtime in seconds, default
`3600`. The HTTP client's `HttpClientTimeout` controls target requests separately.

## Scenarios

```msf

msf > use auxiliary/scanner/garak/garak_ollama
msf auxiliary(scanner/garak/garak_ollama) > set RHOSTS 10.5.134.138
RHOSTS => 10.5.134.138
msf auxiliary(scanner/garak/garak_ollama) > set RPORT 11434
RPORT => 11434
msf auxiliary(scanner/garak/garak_ollama) > set PYTHON /tmp/msf-garak-live-venv/bin/python
PYTHON => /tmp/msf-garak-live-venv/bin/python
msf auxiliary(scanner/garak/garak_ollama) > set PROBE_FILTER test.
PROBE_FILTER => test.
msf auxiliary(scanner/garak/garak_ollama) > set OUTPUT_YAML true
OUTPUT_YAML => true
msf auxiliary(scanner/garak/garak_ollama) > set VERBOSE true
VERBOSE => true
msf auxiliary(scanner/garak/garak_ollama) > show options

Module options (auxiliary/scanner/garak/garak_ollama):

   Name            Current Setting                      Required  Description
   ----            ---------------                      --------  -----------
   OUTPUT_YAML     true                                 yes       Save a garak YAML configuration for each discovered target
   PROBE_FILTER    test.                                no        Optional case-insensitive substring to narrow probe suggestions
   PYTHON          /tmp/msf-garak-live-venv/bin/python  yes       Python executable with the garak package installed
   Proxies                                              no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5, socks5h, http, sapni, socks4
   RHOSTS          10.5.134.138                         yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT           11434                                yes       The target port (TCP)
   SSL             false                                no        Negotiate SSL/TLS for outgoing connections
   SUGGEST_PROBES  true                                 yes       Query model capabilities and suggest probes using local garak metadata
   TARGETURI       /                                    yes       Base path to the Ollama service
   THREADS         1                                    yes       The number of concurrent threads (max one per host)
   VHOST                                                no        HTTP server virtual host

msf auxiliary(scanner/garak/garak_ollama) > run
[+] Ollama service detected
[*] Candidate target types (generation support has not been tested)
===============================================================

  TARGET_TYPE                 Alias for
  -----------                 ---------
  ollama                      ollama.OllamaGeneratorChat
  ollama.OllamaGenerator
  ollama.OllamaGeneratorChat

[*] Available target names
======================

  TARGET_NAME
  -----------
  smollm2:135m

[*] Model smollm2:135m capabilities: completion; identified input types: text
[*] Suggested probes for smollm2:135m (input compatibility only)
============================================================

  PROBES             Inputs  TARGET_TYPE
  ------             ------  -----------
  probes.test.Blank  text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.test.Test   text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator

[*] Probe comparison for smollm2:135m: 2 suggested, 0 with unknown compatibility, 2 considered
[!] Probe suggestions compare declared input types only; dependencies, languages and behavior still need validation
[*] Full probe compatibility results saved to /home/tmoose/.msf4/loot/20261026154636_default_10.5.134.138_ollama.garak.pro_000818.json
[+] Garak YAML configuration saved: /home/tmoose/.msf4/loot/20261026154636_default_10.5.134.138_ollama.garak.con_775283.yaml
[*] Use garak_scan TARGET_TYPE=ollama.OllamaGeneratorChat TARGET_NAME=smollm2:135m CONFIG_FILE=/home/tmoose/.msf4/loot/20261026154636_default_10.5.134.138_ollama.garak.con_775283.yaml PYTHON=/tmp/msf-garak-live-venv/bin/python PROBES=probes.test.Blank VERBOSE=true
[*] Or run in a terminal: /tmp/msf-garak-live-venv/bin/python -m garak --config /home/tmoose/.msf4/loot/20261026154636_default_10.5.134.138_ollama.garak.con_775283.yaml --spec probes.test.Blank
[*] This example tests connectivity only; use garak_list_probes to select security probes
[*] Run garak_scan while this module is active to inherit RHOSTS, RPORT, SSL and TARGETURI
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```



