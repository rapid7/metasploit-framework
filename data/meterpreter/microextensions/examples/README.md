# Meterpreter Microextension Examples

This directory contains non-production reference implementations for the
Meterpreter microextension loader. They demonstrate small resident COFF objects,
manifests, reusable Framework adapters, YAML-defined commands, and Ruby client
helpers on Windows x86 and x64.

These examples are development aids, not supported extensions intended to be
used as-is. Review and adapt the source for the intended target and rebuild it
against the matching Meterpreter source revision.

The manifest format is documented in `docs/manifest.md`.

## Layout

- `include/`: shared Meterpreter microextension ABI and runtime headers.
- `stdapi/`: stdapi sources, private headers, and profile manifests.
- `custom/`: independent sources, optional Ruby helpers, and manifests.
- `build/`: shared x64 and x86 COFF outputs.

The initial features remain independently loadable dependency islands:

- `sysinfo.<arch>.o`: `stdapi_sys_config_sysinfo` (`1059`).
- `listing.<arch>.o`: `stdapi_fs_getwd`, `stdapi_fs_ls`, and `stdapi_fs_stat`
  (`1008`, `1009`, and `1016`).
- `railgun_api.<arch>.o`: `stdapi_railgun_api` (`1028`).

Objects receive the current Meterpreter `MetApi *`, return an ABI v2 command and channel-provider
descriptor from `micro_init`, and use only synchronous handlers in this first
iteration. `core_enumextcmd` and `core_micro_enum` have independent inventories.
The manifest explicitly chooses any built-in client adapter and the UI commands
it exposes; enumeration alone never activates a client or dispatcher. Ruby is optional and used only for manifest-owned client helpers.

## Full FS command namespace

The FS implementation is split into dependency islands rather than one large
object:

- `listing.<arch>.o`: working directory, directory listing, and stat.
- `fs_file.<arch>.o`: native pool channels for `stdapi_fs_file`.
- `fs_operations.<arch>.o`: chdir, chmod, delete, copy, move, expand, mkdir,
  and separator.
- `fs_hash.<arch>.o`: MD5 and SHA1.
- `fs_mount.<arch>.o`: logical drives and mount metadata.
- `fs_search.<arch>.o`: recursive search and modification-time filtering.

Together they implement command IDs `1001..1016` plus the canonical file-channel type. `micro-stdapi.yaml` uses one
shared `stdapi_fs` compatibility adapter after all objects have loaded.
`micro-stdapi-yaml.yaml` renders packet commands and delegates file UI through `micro run`. The file data plane remains a core-channel capability rather than a synthetic FS command ID.

## YAML UI

`custom/manifests/micro-yaml-ui.yaml` defines a complete command presentation:
name, description, command ID, arguments, TLV types, response fields, and
formatting. Its `echo.<arch>.o` has no Framework adapter. From the Framework
repository root, test it with:

```text
micro load ./data/meterpreter/microextensions/examples/custom/manifests/micro-yaml-ui.yaml
micro
micro has echo
micro run echo "hello from yaml"
```

The expected response is `Target echoed: hello from yaml`.

## YAML micro-stdapi UI

`stdapi/manifests/micro-stdapi-yaml.yaml` is the same reduced profile with the
operator UI for system and filesystem commands defined in YAML. It deliberately does not expose the `stdapi_sys` or `stdapi_fs` dispatchers as top-level headings. YAML-selected file commands reuse the generic `stdapi_fs` client adapter. Railgun retains an
API-only adapter so existing post modules can call its canonical API. Test it in
a fresh session with:

```text
micro load ./data/meterpreter/microextensions/examples/stdapi/manifests/micro-stdapi-yaml.yaml
micro
micro alias micro-stdapi-yaml
sysinfo
ls C:/Windows
micro run sysinfo
micro run pwd
micro run ls
micro run ls C:/Windows
micro run stat C:/Windows/notepad.exe
micro run edit C:/Windows/Temp/note.txt
micro run cat C:/Windows/win.ini
micro run upload ./local.txt C:/Windows/Temp/
micro run download C:/Windows/win.ini ./win.ini
micro alias ls dir
dir C:/Windows
run post/windows/gather/forensics/enum_drives MAXDRIVES=0
```

## Custom Ruby helper

`custom/manifests/micro-file-helper.yaml` demonstrates a file-backed controller
helper without the stdapi Ruby adapter. In a fresh session:

```text
micro load ./data/meterpreter/microextensions/examples/custom/manifests/micro-file-helper.yaml
micro run download C:/Windows/win.ini ./win.ini
micro alias micro-file-helper
download C:/Windows/win.ini ./win.ini
```

Its optional `custom_fs` API alias is available to post code as
`client.custom_fs.download(remote_path, local_path)`. The same helper body can
be embedded under `client.helper.source` in a manifest.

## Build

The object files are intentionally not committed. Build and inspect them from
this directory with an explicit path to a matching `metasploit-payloads`
checkout:

```sh
make PAYLOADS=/absolute/path/to/metasploit-payloads
make PAYLOADS=/absolute/path/to/metasploit-payloads verify
```

The examples use Meterpreter's internal `MetApi` ABI. Rebuild them whenever that
ABI changes and use them only with the compatible Meterpreter build.

## Status

The objects, loader-facing ABI v2 descriptors, and `stdapi_fs_file` provider are implemented. Unload returns `ERROR_BUSY` while one of its channels is open. Railgun supports up
to 16 native arguments and 16 MiB of aggregate buffer data in this first
slice.

## Test

Build and install the matching metsrv from the `feat/meterpreter/microextensions`
branch of the sibling payload repository, then start a Windows x86 or x64
Meterpreter without conventional extensions (`AutoLoadExtensions []`,
`AutoLoadStdapi false`, `AutoSystemInfo false`).
In the session run:

```text
micro load ./data/meterpreter/microextensions/examples/stdapi/manifests/micro-stdapi.yaml
micro list
micro has stdapi_sys_config_sysinfo stdapi_fs_ls stdapi_railgun_api
cat C:/Windows/win.ini
upload ./local.txt C:/Windows/Temp/
download C:/Windows/win.ini ./win.ini
sysinfo
ls
run post/windows/gather/forensics/enum_drives MAXDRIVES=0
```

Unload an individual dependency island by its listed name or handle. Loading
the manifest is transactional: Framework unloads earlier objects when a later
object or client adapter cannot be initialized.
