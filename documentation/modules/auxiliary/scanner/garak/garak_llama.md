## Vulnerable Application

This module discovers garak target values from a llama.cpp server. It reads
`/v1/models` and, when probe suggestions are enabled, `/props`. It submits no
prompts and does not establish that a model is vulnerable. Model records must
identify their owner as `llamacpp`; generic OpenAI-compatible services are not
reported as llama.cpp.

For a local test server, place a GGUF model in a local `models` directory and run:

```sh
docker run --name garak-llama-cpp -p 8080:8080 \
  -v "$PWD/models:/models:ro" ghcr.io/ggml-org/llama.cpp:server \
  -m /models/model.gguf --alias test-model --host 0.0.0.0 --port 8080
```

See the [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/tree/master/tools/server)
for model and server requirements. Probe suggestions require a local garak
checkout and a Python environment containing its dependencies, as described in
[garak_integration](garak_integration.md).

The scanner prints TARGET_TYPE, TARGET_NAME and PROBES tables. Suggestions compare
declared inputs only; dependencies, language and actual model behavior are not
tested. Missing model or plugin capabilities remain unknown. Properties apply
only to their named model. Image probes require both model and generator support;
a vision model alone does not establish that garak's adapter accepts images.

Discovered targets are recorded as `llama.garak.targets` database notes. Full
probe comparisons are saved as JSON loot and `llama.garak.probes` notes. No
vulnerability records are created.

## Verification Steps

1. Start a llama.cpp server with a model and install local garak dependencies.
2. Start msfconsole and select `auxiliary/scanner/garak/garak_llama`.
3. Set `RHOSTS` and `RPORT` to the server.
4. Set `PYTHON` to the garak environment's Python executable.
5. Set `GARAK_PATH` to the checkout if it is not beside Metasploit.
6. Run `run verbose=true` and inspect the target and probe tables.
7. Use the discovered values in `auxiliary/scanner/garak/garak_integration`, keeping
   the same host, port and SSL settings, but appending `/v1/` to the base path
   for that module's `TARGETURI` (normally `/v1/`).
8. Supply garak's API key in CONFIG_FILE or OPENAICOMPATIBLE_API_KEY. Garak needs
   a nonempty placeholder such as `unused` even for an unauthenticated server.

Set `TARGETURI` to the service base path, normally `/`. Do not include `/v1/`;
the scanner constructs both `/v1/models` and `/props` below this path.

## Options

### API_KEY

Optional bearer token for protected servers. This value is used for discovery
requests only; configure credentials separately for garak_integration.

### SUGGEST_PROBES

Defaults to true. Set false for target discovery without local Python or garak.

### PROBE_FILTER

Optional case-insensitive substring selecting probe names. No filter compares
all probes in the installed garak metadata. No LIST_PROBES action is provided.

### GARAK_PATH

Local garak checkout. Defaults to the garak directory beside Metasploit.

### PYTHON

Python executable with garak dependencies installed. For example,
`/home/user/.local/share/pipx/venvs/garak/bin/python`.

### RunTimeout

Advanced option limiting the local metadata query, in seconds. Defaults to 3600.

## Scenarios

```msf
msf auxiliary(scanner/garak/garak_llama) > show options

Module options (auxiliary/scanner/garak/garak_llama):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   API_KEY                          no        Bearer API key if the server requires authentication
   GARAK_PATH                       no        Local garak checkout; defaults to the garak directory beside Met
                                              asploit
   PROBE_FILTER                     no        Case-insensitive substring to narrow probe suggestions
   PYTHON          python3          yes       Python executable with garak dependencies installed
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]. Su
                                              pported proxies: socks5, socks5h, sapni, http, socks4
   RHOSTS                           yes       The target host(s), see https://docs.metasploit.com/docs/using-m
                                              etasploit/basics/using-metasploit.html
   RPORT           8080             yes       The target port (TCP)
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   SUGGEST_PROBES  true             yes       Compare model capabilities with local garak metadata
   TARGETURI       /                yes       Base path to the llama.cpp service (without /v1)
   THREADS         1                yes       The number of concurrent threads (max one per host)
   VHOST                            no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(scanner/garak/garak_llama) > set GARAK_PATH /home/tmoose/git/garak
GARAK_PATH => /home/tmoose/git/garak
msf auxiliary(scanner/garak/garak_llama) > set PYTHON /home/tmoose/.local/share/pipx/venvs/garak/bin/python
PYTHON => /home/tmoose/.local/share/pipx/venvs/garak/bin/python
msf auxiliary(scanner/garak/garak_llama) > set rhosts 10.5.135.119
rhosts => 10.5.135.119
msf auxiliary(scanner/garak/garak_llama) > set PROBE_FILTER dan
PROBE_FILTER => dan
msf auxiliary(scanner/garak/garak_llama) > set verbose true
verbose => true
msf auxiliary(scanner/garak/garak_llama) > run
[+] Llama.cpp models detected
[*] Candidate target types (generation support has not been tested)
===============================================================

  TARGET_TYPE
  -----------
  openai.OpenAICompatible

[*] Available target names
======================

  TARGET_NAME
  -----------
  qwen2.5-1.5b-instruct

[*] Model qwen2.5-1.5b-instruct capabilities: completion; identified input types: text
[*] Suggested probes for qwen2.5-1.5b-instruct (input compatibility only)
=====================================================================

  PROBES                                   Inputs  TARGET_TYPE
  ------                                   ------  -----------
  probes.dan.Ablation_Dan_11_0             text    openai.OpenAICompatible
  probes.dan.AntiDAN                       text    openai.OpenAICompatible
  probes.dan.AutoDAN                       text    openai.OpenAICompatible
  probes.dan.AutoDANCached                 text    openai.OpenAICompatible
  probes.dan.ChatGPT_Developer_Mode_RANTI  text    openai.OpenAICompatible
  probes.dan.ChatGPT_Developer_Mode_v2     text    openai.OpenAICompatible
  probes.dan.ChatGPT_Image_Markdown        text    openai.OpenAICompatible
  probes.dan.DAN_Jailbreak                 text    openai.OpenAICompatible
  probes.dan.DUDE                          text    openai.OpenAICompatible
  probes.dan.DanInTheWild                  text    openai.OpenAICompatible
  probes.dan.DanInTheWildFull              text    openai.OpenAICompatible
  probes.dan.Dan_10_0                      text    openai.OpenAICompatible
  probes.dan.Dan_11_0                      text    openai.OpenAICompatible
  probes.dan.Dan_6_0                       text    openai.OpenAICompatible
  probes.dan.Dan_6_2                       text    openai.OpenAICompatible
  probes.dan.Dan_7_0                       text    openai.OpenAICompatible
  probes.dan.Dan_8_0                       text    openai.OpenAICompatible
  probes.dan.Dan_9_0                       text    openai.OpenAICompatible
  probes.dan.STAN                          text    openai.OpenAICompatible

[*] Probe comparison for qwen2.5-1.5b-instruct: 19 suggested, 0 with unknown compatibility, 19 considered
[!] Probe suggestions compare declared input types only; dependencies, languages and behavior still need validation
[*] Full probe compatibility results saved to /home/tmoose/.msf4/loot/20260930111948_default_10.5.135.119_llama.garak.prob_586155.json
[*] Use these values with auxiliary/scanner/garak/garak_integration, the same RHOSTS/RPORT/SSL and TARGETURI /v1/
[*] Garak requires an API key value; provide the actual key or an unused placeholder for an unauthenticated server through CONFIG_FILE or OPENAICOMPATIBLE_API_KEY
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```