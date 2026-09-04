## Vulnerable Application

[vLLM](https://github.com/vllm-project/vllm) is a high-throughput inference and
serving engine for large language models that exposes an OpenAI-compatible HTTP
API. Versions **0.8.3 through 0.14.0** are affected by
[CVE-2026-22778](https://github.com/vllm-project/vllm/security/advisories/GHSA-4r2x-xpjr-7cvv)
(CVSS 9.8), fixed in **0.14.1**.

When an invalid image is sent to a multimodal endpoint, Pillow (PIL) raises
`UnidentifiedImageError` whose message embeds the Python repr of the underlying
`BytesIO` buffer (`<_io.BytesIO object at 0x...>`), exposing a live heap address.
Vulnerable versions return that error message verbatim to an unauthenticated
client. The leak weakens ASLR and is the first stage of a chain that ends in a
JPEG2000 heap overflow in the bundled FFmpeg/OpenCV video decoder (RCE). The
0.14.1 fix adds `sanitize_message`, which collapses the repr to
`<_io.BytesIO object>` with the address removed.

This module reads the unauthenticated `/version` banner and range-checks it,
auto-detects the served model through `/v1/models` (overridable with `MODEL`),
and sends a single benign request to `/v1/chat/completions` carrying a
deliberately malformed base64 image. Classification is behavior-first: a leaked
`0x` heap address is reported **Vulnerable**; a sanitized message is reported
**Safe** (0.14.1 fix present); an in-range version with no reachable multimodal
model is reported **Appears**; a version outside the affected range is reported
**Safe**. The probe never sends a video URL and never reaches the heap-overflow
code path (CRASH_SAFE).

A separate companion module targets the Anthropic `/v1/messages` router
(CVE-2026-54236), which remained vulnerable after the OpenAI-router fix landed.

### Setup with Docker

Stand up a vLLM server with an image-capable model. Any version exercises the
module; `0.14.1+` exercises the patched (sanitized) path:

```
docker run -d -p 8000:8000 vllm/vllm-openai-cpu:latest-x86_64 \
  --model llava-hf/llava-interleave-qwen-0.5b-hf --max-model-len 4096 --enforce-eager
```

The model takes a short while to load; wait until `GET /v1/models` returns the
model id before running the module.

## Verification Steps

1. Start a vLLM server with a multimodal model (see Setup with Docker)
1. Start `msfconsole`
1. Do: `use auxiliary/scanner/http/vllm_multimodal_info_leak`
1. Do: `set RHOSTS <target>`
1. Do: `run`
1. On a vulnerable server (0.8.3 - 0.14.0) the module reports **Vulnerable** with the leaked heap address; on a patched server it reports **Safe**

## Options

### TARGETURI

The base path to the vLLM OpenAI-compatible API. Defaults to `/`. Set this when
vLLM is served from a sub-path behind a reverse proxy.

### MODEL

The model name used in the probe request. When empty (default) the module
auto-detects the served model from the first entry of `/v1/models`. Set this to
target a specific model when several are served.

## Scenarios

### vLLM 0.13.0 (vulnerable)

```
msf6 > use auxiliary/scanner/http/vllm_multimodal_info_leak
msf6 auxiliary(scanner/http/vllm_multimodal_info_leak) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/vllm_multimodal_info_leak) > run

[+] 127.0.0.1:8000        - Heap-address leak confirmed via malformed image (vLLM 0.13.0)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### vLLM 0.23.0 (patched, true-negative)

```
msf6 auxiliary(scanner/http/vllm_multimodal_info_leak) > run

[*] 127.0.0.1:8000        - Error message sanitized; CVE-2026-22778 fix present (vLLM 0.23.0)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
