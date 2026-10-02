## Vulnerable Application

This module identifies Ollama services and provides garak target configuration.
It requires the `Ollama is running` banner at the base path, then queries
[`GET /api/tags`](https://docs.ollama.com/api/tags) for installed model names.
No vulnerability is required. By default, the scanner queries each model with
`POST /api/show` and compares its capabilities with local garak probe and adapter
metadata. This requires a local garak checkout and a Python environment with its
dependencies installed. Set `SUGGEST_PROBES false` for target discovery without
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
identified inputs, garak version, and each considered probe's status for each
adapter: `suggested`, `incompatible`, or `unknown`. Unknown model capabilities
produce no suggestions. Failure to retrieve `/api/show` does not discard the
already discovered model names.

These are input-type suggestions, not proof of compatibility or vulnerability.
They include active and inactive probes present in garak's metadata. Language,
credentials, dependencies, resource use and behavioral prerequisites still need
review before running them. Metadata is obtained through garak's plugin API;
no probes or generators are instantiated by the metadata helper.

## Verification Steps

1. Start an Ollama instance and install a model.
1. Start `msfconsole`.
1. Do: `use auxiliary/scanner/garak/garak_ollama`.
1. Do: `set RHOSTS 127.0.0.1`.
1. Set `GARAK_PATH` to the local garak checkout and `PYTHON` to its interpreter.
1. Do: `run verbose=true`.
1. Confirm that `TARGET_TYPE` candidates, installed `TARGET_NAME` values and
   capability-based probe suggestions appear.
1. Use these values with `auxiliary/scanner/garak/garak_integration`, retaining the
   same `RHOSTS`, `RPORT`, `SSL` and `TARGETURI`. Select `PROBES` separately.

The default port is `11434`. For a reverse proxy mounted at `/ollama/`, set
`TARGETURI` to `/ollama/`; the model query uses `/ollama/api/tags`.
Use the HTTP client's SSL, authentication, proxy and timeout options as needed.
Authentication for garak itself must be configured separately.

## Options

### SUGGEST_PROBES

Defaults to `true`. Query model capabilities and compare against local garak
metadata. Set to `false` to discover only target types and names without garak.
There is no LIST_PROBES action; suggestions are part of the scan.

### GARAK_PATH

Local garak source checkout. If unset, use the `garak` directory beside the
Metasploit checkout. Used when `SUGGEST_PROBES` is enabled.

### PYTHON

Python executable with garak's dependencies installed, default `python3`.
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
msf auxiliary(scanner/garak/garak_ollama) > show options

Module options (auxiliary/scanner/garak/garak_ollama):

   Name            Current Setting                Required  Description
   ----            ---------------                --------  -----------
   GARAK_PATH      /home/tmoose/git/garak         no        Local garak checkout; defaults to the garak direct
                                                            ory beside Metasploit
   PROBE_FILTER    dan                            no        Optional case-insensitive substring to narrow prob
                                                            e suggestions
   PYTHON          /home/tmoose/.local/share/pip  yes       Python executable with garak dependencies installe
                   x/venvs/garak/bin/python                 d
   Proxies                                        no        A proxy chain of format type:host:port[,type:host:
                                                            port][...]. Supported proxies: socks5, socks5h, sa
                                                            pni, http, socks4
   RHOSTS          10.5.135.119                   yes       The target host(s), see https://docs.metasploit.co
                                                            m/docs/using-metasploit/basics/using-metasploit.ht
                                                            ml
   RPORT           11434                          yes       The target port (TCP)
   SSL             false                          no        Negotiate SSL/TLS for outgoing connections
   SUGGEST_PROBES  true                           yes       Query model capabilities and suggest probes using
                                                            local garak metadata
   TARGETURI       /                              yes       Base path to the Ollama service
   THREADS         1                              yes       The number of concurrent threads (max one per host
                                                            )
   VHOST                                          no        HTTP server virtual host


View the full module info with the info, or info -d command.

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
  qwen2.5:3b

[*] Model qwen2.5:3b capabilities: completion, tools; identified input types: text
[*] Suggested probes for qwen2.5:3b (input compatibility only)
==========================================================

  PROBES                                   Inputs  TARGET_TYPE
  ------                                   ------  -----------
  probes.dan.Ablation_Dan_11_0             text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.AntiDAN                       text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.AutoDAN                       text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.AutoDANCached                 text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.ChatGPT_Developer_Mode_RANTI  text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.ChatGPT_Developer_Mode_v2     text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.ChatGPT_Image_Markdown        text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.DAN_Jailbreak                 text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.DUDE                          text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.DanInTheWild                  text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.DanInTheWildFull              text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.Dan_10_0                      text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.Dan_11_0                      text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.Dan_6_0                       text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.Dan_6_2                       text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.Dan_7_0                       text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.Dan_8_0                       text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.Dan_9_0                       text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator
  probes.dan.STAN                          text    ollama.OllamaGeneratorChat, ollama.OllamaGenerator

[*] Probe comparison for qwen2.5:3b: 19 suggested, 0 with unknown compatibility, 19 considered
[!] Probe suggestions compare declared input types only; dependencies, languages and behavior still need validation
[*] Full probe compatibility results saved to /home/tmoose/.msf4/loot/20260930111650_default_10.5.135.119_ollama.garak.pro_447447.json
[*] Use these values with auxiliary/scanner/garak/garak_integration and the same RHOSTS, RPORT, SSL and TARGETURI
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```



