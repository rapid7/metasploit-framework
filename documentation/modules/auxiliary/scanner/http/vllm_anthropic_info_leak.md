## Vulnerable Application

[vLLM](https://github.com/vllm-project/vllm) is a high-throughput inference and
serving engine for large language models that exposes an OpenAI-compatible HTTP
API. Versions **up to and including 0.23.0** are affected by
[CVE-2026-54236](https://advisories.gitlab.com/pypi/vllm/CVE-2026-54236/)
([GHSA-hgg8-fqqc-vfmw](https://github.com/advisories/GHSA-hgg8-fqqc-vfmw)), an
incomplete fix for [CVE-2026-22778](https://github.com/vllm-project/vllm/security/advisories/GHSA-4r2x-xpjr-7cvv).

The CVE-2026-22778 fix added `sanitize_message` to the OpenAI router's exception
handlers, so a malformed image submitted to `/v1/chat/completions` no longer
leaks the Python repr of Pillow's underlying `BytesIO` buffer
(`<_io.BytesIO object at 0x...>`, a live heap address). The Anthropic-compatible
router (`/v1/messages`, added in early 2026) and the speech-to-text endpoints,
however, echo `str(exc)` directly. The same malformed image therefore still leaks
the heap address verbatim through those paths to an unauthenticated client. The
leak weakens ASLR and is the entry primitive of the CVE-2026-22778 chain that ends
in a JPEG2000 heap overflow in the bundled FFmpeg/OpenCV video decoder. No fixed
release was available at disclosure; the fix is pending in
[vllm-project/vllm#45119](https://github.com/vllm-project/vllm/pull/45119).

This module reads the unauthenticated `/version` banner, auto-detects the served
model through `/v1/models` (overridable with `MODEL`), and sends a single benign
request to `/v1/messages` carrying a deliberately malformed base64 image. A
response that leaks a `0x` heap address is reported **Vulnerable**; a sanitized
message or an absent `/v1/messages` endpoint is reported **Safe**. The probe never
sends a video URL and never reaches the heap-overflow code path (CRASH_SAFE).

This module complements a separate scanner for the OpenAI
`/v1/chat/completions` router (CVE-2026-22778). On a server patched for
CVE-2026-22778 but not CVE-2026-54236 the two endpoints behave differently, so a
separate module is warranted.

### Setup with Docker

Stand up a vLLM server with an image-capable model. vLLM `0.23.0` (the latest
release at disclosure) still leaks through `/v1/messages` while its OpenAI path is
already sanitized:

```
docker run -d -p 8000:8000 vllm/vllm-openai-cpu:latest-x86_64 \
  --model llava-hf/llava-interleave-qwen-0.5b-hf --max-model-len 4096 --enforce-eager
```

The model takes a short while to load; wait until `GET /v1/models` returns the
model id before running the module.

## Verification Steps

1. Start a vLLM server with a multimodal model (see Setup with Docker)
1. Start `msfconsole`
1. Do: `use auxiliary/scanner/http/vllm_anthropic_info_leak`
1. Do: `set RHOSTS <target>`
1. Do: `run`
1. On an affected server the module reports **Vulnerable** with the leaked heap address; on a server patched for CVE-2026-54236 it reports **Safe**

## Options

### TARGETURI

The base path to the vLLM OpenAI-compatible API. Defaults to `/`. Set this when
vLLM is served from a sub-path behind a reverse proxy.

### MODEL

The model name used in the probe request. When empty (default) the module
auto-detects the served model from the first entry of `/v1/models`. Set this to
target a specific model when several are served.

## Scenarios

### vLLM 0.23.0 (vulnerable via the Anthropic router)

```
msf6 > use auxiliary/scanner/http/vllm_anthropic_info_leak
msf6 auxiliary(scanner/http/vllm_anthropic_info_leak) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/vllm_anthropic_info_leak) > run

[+] 127.0.0.1:8000        - Heap-address leak confirmed via Anthropic /v1/messages (vLLM 0.23.0)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### vLLM patched for CVE-2026-54236 (true-negative)

```
msf6 auxiliary(scanner/http/vllm_anthropic_info_leak) > run

[*] 127.0.0.1:8000        - /v1/messages error is sanitized; not vulnerable (vLLM 0.23.1)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
