# Microextension YAML Manifest Guide

A microextension manifest declares which COFF objects belong to a profile, the
commands and channel providers each object must register, and how Framework
should expose their client-side interface. The manifest is configuration and UI
metadata. Target-side behavior comes from the COFF object; an optional trusted
Ruby helper can provide executable client-side behavior.

The parser validates the fields described below, but it is not a closed-schema
validator. Unknown keys in top-level, object, client, UI, request, response, and
output mappings are currently ignored. The `client.helper` mapping is the
exception: it rejects keys other than `alias`, `file`, and `source`.

## Minimal manifest

```yaml
schema: meterpreter-micro/v1
profile: micro-tools
platform: windows
architecture: [x64, x86]
objects:
  - name: micro-sysinfo
    file:
      x64: ../../build/sysinfo.x64.o
      x86: ../../build/sysinfo.x86.o
    commands:
      - { id: 1059, name: stdapi_sys_config_sysinfo }
```

Load it with:

```text
micro load /path/to/micro-tools.yaml
micro list
micro has stdapi_sys_config_sysinfo
```

Paths in `file` are resolved relative to the manifest.

## Top-level keys

| Key | Required | Description |
| --- | --- | --- |
| `schema` | Yes | Must currently be `meterpreter-micro/v1`. |
| `profile` | Yes | Profile name used by `micro alias`; must match `[a-z][a-z0-9_-]*`. |
| `platform` | Yes | Must currently be `windows`. |
| `architecture` | Yes | String or list containing the current session architecture, `x64` or `x86`. |
| `metapi_source_commit` | No | Informational source pin. It is not currently enforced by the loader. |
| `objects` | Yes | Ordered list of independently loadable COFF objects. |

## Object declarations

```yaml
objects:
  - name: micro-stdapi-listing
    file:
      x64: ../../build/listing.x64.o
      x86: ../../build/listing.x86.o
    commands:
      - { id: 1008, name: stdapi_fs_getwd }
      - { id: 1009, name: stdapi_fs_ls }
    channels: []
    client:
      adapter: stdapi_fs
      expose: [pwd, ls]
    ui:
      commands: []
```

| Key | Required | Description |
| --- | --- | --- |
| `name` | Yes | Non-empty string that must exactly equal the name returned by the object's `micro_init` descriptor. |
| `file` | Yes | One object path, or an `x64`/`x86` path map. |
| `commands` | Yes | Expected canonical command IDs. Use `[]` for a provider-only object. |
| `channels` | No | Expected named channel providers, such as `stdapi_fs_file`. Defaults to `[]`. |
| `client` | No | Installs an existing generic Framework API/UI adapter. |
| `ui` | No | Declares commands handled by `micro run` and optional aliases. |

Framework checks the object's architecture before upload. After loading, it
compares the command IDs and channel types returned by Meterpreter with this
manifest. A mismatch aborts the profile and unloads objects already loaded by
that transaction.

### Commands

Each command entry must be a mapping with a required integer `id`. `name`
documents the canonical command name but is not consumed by the Framework
parser:

```yaml
commands:
  - id: 1059
    name: stdapi_sys_config_sysinfo
```

Do not create synthetic command IDs for channel operations. For example, file
I/O uses the core `core_channel_*` commands and declares `stdapi_fs_file` under
`channels` instead.

`micro has` resolves numeric IDs, canonical command names already known to
Framework, and the names of currently loaded direct YAML commands. It does not
resolve an arbitrary `commands[].name`. A custom command named `micro_echo` in
this list and exposed as the UI command `echo` is queried with `micro has echo`
or its numeric ID.

### Channel providers

A provider-only object declares an empty command list and at least one channel:

```yaml
- name: micro-stdapi-file-channel
  file:
    x64: ../../build/fs_file.x64.o
    x86: ../../build/fs_file.x86.o
  channels: [stdapi_fs_file]
  commands: []
```

The declaration does not implement the provider. The corresponding ABI v2 COFF
object must return the same provider type and native `open` callback from
`micro_init`. Meterpreter owns channel IDs and dispatches `read`, `write`,
`seek`, `tell`, `eof`, and `close` through that object. The object cannot be
unloaded while any provider-created channel is open.

## Client adapters

A client adapter activates an existing generic Framework API. It does not load
a conventional target extension:

```yaml
client:
  adapter: stdapi_fs
  expose: [cat, download, edit, upload]
```

- `adapter` must name an installed adapter, such as `stdapi_fs`, `stdapi_sys`, or
  `stdapi_railgun`.
- `expose` lists standard console commands that become top-level commands.
- `expose: []` installs only the programmatic API, unless a YAML delegate needs
  the adapter's hidden UI implementation.
- Objects using the same adapter are wired as one dependency group after all
  objects load. UI commands are removed as their declaring object's commands or
  channels disappear.
- Framework rejects a micro adapter when that adapter or its conventional
  extension is already active. Use a fresh session without auto-loaded stdapi.

For example, `stdapi_fs` supplies `client.fs.file`, while `stdapi_railgun`
supplies `client.railgun` for compatible post modules.

## Direct YAML UI commands

A direct command creates a Meterpreter request from positional arguments and
renders its response without microextension-specific Ruby code:

```yaml
ui:
  commands:
    - name: pwd
      description: Display the target working directory
      request:
        command: 1008
      response:
        fields:
          - { name: path, type: string, tlv: 1200 }
      output:
        format: "Working directory: %{path}"
```

The request `command` must be declared in the same object's `commands` list.
Run it with `micro run pwd`.

Every `ui.commands` entry requires:

- `name`: a command name matching `[a-z][a-z0-9_]*` that does not duplicate an
  already loaded manifest command.
- `description`: a string shown by `micro` help.
- Either a `delegate` mapping, or `request` and `output` mappings for a direct
  command. `response` may be omitted when the command has no response fields or
  rows to render.

`has`, `help`, `list`, `load`, `run`, and `unload` are reserved command names.
When `delegate` is present, the direct request, response, and output mappings
are ignored.

### Arguments

Arguments are positional and become request TLVs:

```yaml
request:
  command: 1009
  arguments:
    - name: path
      type: string
      tlv: 1200
      required: false
      default: "."
```

Argument names must match `[a-z][a-z0-9_]*`. Supported types are `string`,
`uint`, `qword`, and `bool`. `required` defaults to `true` and must be a YAML
boolean when present. Optional arguments require a `default` key.

Arguments are bound strictly by position. Put required arguments before
optional arguments; there is no syntax for skipping an optional argument in
the middle. Calls with fewer than the total required argument count or more
than the declared argument count print the generated usage and are not sent.

Console arguments and defaults are converted from strings at execution time.
Quote defaults for `bool`, `uint`, and `qword` in YAML. Boolean input is exactly
`"true"` or `"false"`. Integer strings accept decimal or `0x` hexadecimal
notation; `uint` accepts `0..0xffffffff` and `qword` accepts
`0..0xffffffffffffffff`. String values are sent unchanged.

The `tlv` value is an integer from `0` through `65535`, representing the low
16-bit TLV number rather than a full encoded TLV type. Framework combines it
with the metadata type selected by `type`.

### Scalar responses

`response.fields` reads one TLV per field. Supported types are `string`, `uint`,
`qword`, `bool`, and `raw`. Field names and TLV numbers follow the same rules as
arguments. `required` and `default` have no effect on response fields. Raw
fields are printed as lowercase hexadecimal.

Output can contain one format:

```yaml
output: { format: "%{path}" }
```

Or multiple lines:

```yaml
output:
  lines:
    - "Computer: %{computer}"
    - "OS:       %{os}"
```

Line output requires either `format` containing a string or `lines` containing
an array of strings. If both are supplied, `lines` wins. Formatting uses Ruby
named `String#%` interpolation. Placeholders should match response field names;
this is not checked while loading the manifest. A missing field produces a
`nil` value and may render as an empty value or produce a command-time format
error depending on the conversion.

### Repeated rows and tables

Use `response.rows` for repeated scalar TLVs, nested group TLVs, or structured
raw TLVs. Any non-empty `rows` list requires table output.

A repeated scalar row has the same name, type, and TLV fields as a normal
response field and supports `string`, `uint`, `qword`, and `bool`:

```yaml
response:
  rows:
    - { name: drive, type: string, tlv: 1325 }
output:
  type: table
  header: Drives
  columns:
    - { label: Drive, name: drive }
```

A group row supplies fields read from each repeated group:

```yaml
response:
  rows:
    - name: mount
      type: group
      tlv: 1325
      fields:
        - { name: name, type: string, tlv: 1200 }
        - { name: size, type: qword, tlv: 1210 }
```

This example decodes a repeated structured raw value:

```yaml
response:
  rows:
    - name: stat
      type: raw
      tlv: 1221
      extract:
        - { name: mode, type: uint, offset: 4 }
        - { name: size, type: qword, offset: 32 }
output:
  type: table
  header: Listing
  columns:
    - { label: Mode, name: mode, display: octal }
    - { label: Size, name: size }
```

A `raw` row requires an `extract` array. Raw extraction supports little-endian
`uint` and `qword` values at non-negative byte offsets. Structured raw rows use
the Meterpreter complex TLV metadata bit, despite the manifest spelling being
`type: raw`. An empty extraction array is accepted and exposes the raw byte
string as the row value.

When several row definitions are present, the renderer combines values with
the same occurrence index and emits as many table rows as the longest TLV list.
A shorter list contributes `nil` to subsequent rows.

If `response.rows` is non-empty, table rendering ignores `response.fields`.

Table output requires `type: table`, a string `header`, and an array of
`columns`. Each column requires string `label` and `name` values. Table display
modes are `raw` (default), `octal`, and `unix_time`. Every column `name` should
match a scalar row, group field, or extracted field. The parser does not verify
that relationship, so invalid conversions or names may fail while rendering
the command response.

## YAML delegates

Some standard commands implement complex client-side behavior, option parsing,
or streaming that the scalar YAML renderer should not duplicate. A delegate
selects that existing generic adapter behavior:

```yaml
channels: [stdapi_fs_file]
commands: []
client:
  adapter: stdapi_fs
  expose: []
ui:
  commands:
    - name: download
      description: Download a target file or directory
      delegate: { adapter: stdapi_fs, command: download }
```

The delegate adapter must equal the object's `client.adapter`, `command` must be
a non-empty string, and the object must declare at least one channel provider.
Both `micro run download ...` and an alias are intended to execute the selected
adapter implementation. This provides manifest-selected UI with no
microextension-specific Ruby, but it still relies on generic Framework adapter
code already present on the operator side.

Current client adapter/delegate wiring is incomplete after manifest validation.
In particular, hidden dispatchers are not initialized for
`expose: []`. Treat delegate manifests as schema and integration examples until
that wiring is corrected.

## Ruby client helpers

Use a helper when controller-side behavior is too complex for the scalar YAML
renderer, but should remain packaged beside the object instead of being added
to Framework. Helpers do not load a conventional target extension or a built-in
stdapi client adapter.

### File-backed helper

```yaml
client:
  helper:
    file: ../helpers/custom_download.rb
    alias: custom_fs
```

The path is relative to the manifest. Its contents are evaluated as the body of
an isolated subclass of `Rex::Post::Meterpreter::MicroHelper`:

```ruby
command 'download', 'Custom channel download' do |remote_path, local_path|
  download(remote_path, local_path)
end

def download(remote_path, local_path)
  channel = open_pool_channel(
    'micro_file_download/v1',
    tlvs: [
      { 'type' => TLV_META_TYPE_STRING | 21_001, 'value' => remote_path }
    ]
  )
  # Consume channel.read and write the result locally.
ensure
  channel&.close
end
```

The optional manifest `alias` registers the helper instance as a programmatic
client API. With `alias: custom_fs`, post code can call
`client.custom_fs.download(...)`. This is independent of operator command
aliases created by `micro alias`.

### Embedded helper

Replace `file` with inline source:

```yaml
client:
  helper:
    alias: micro_api
    source: |
      command 'hello', 'Test an inline helper' do |name|
        print_line("Hello #{name}")
      end
```

Exactly one non-empty `file` or `source` is required. A helper may be combined
with direct YAML UI, but not with `client.adapter` or `client.expose`.

A helper must register at least one helper command or declare a client API
`alias`. Helper command names and descriptions follow the direct UI command
rules; commands must have handlers and cannot duplicate another helper or
loaded manifest command. A client API alias must match `[a-z][a-z0-9_]*` and
cannot replace any method already exposed by the Meterpreter client.

### Helper interface

- `command(name, description) { |*arguments| ... }` registers a `micro run`
  command. `micro alias <profile|object|command>` can promote it.
- `client` exposes the current Meterpreter client.
- `shell` exposes the Meterpreter console.
- `profile`, `object_name`, and `channel_types` expose the manifest scope and
  channel providers declared by the helper's object.
- `open_pool_channel(type, tlvs:, flags:)` opens a declared provider through
  `core_channel_open` and returns the generic Meterpreter pool channel.
- `print`, `print_line`, `print_status`, `print_good`, `print_warning`, and
  `print_error` write through the current console.
- `on_unload { ... }` registers optional local cleanup.
- Normal instance methods become available through the optional client API
  alias.

A helper is tied to the same target features as its object. Framework removes
its `micro run` commands and client API alias and invokes `on_unload` after that
object is unloaded. Helper source is limited to 1 MiB.

Helpers execute trusted Ruby with the msfconsole process's permissions. This
removes extension-specific source from the Framework repository, not the
Framework runtime dependency. Controllers implemented in another language need
an equivalent implementation or a data-only YAML action.

A working file-backed example is `custom/helpers/custom_download.rb`, loaded by
`custom/manifests/micro-file-helper.yaml`. It uses the generic pool-channel API and
does not instantiate the stdapi Ruby adapter.

## Unload lifecycle

Framework refreshes the complete remote microextension inventory after every
unload. Client-side features are then retained according to these rules:

- A direct UI command remains while its request command ID remains registered.
- A delegated command remains only while every channel type declared by its
  object remains registered.
- A helper remains only while all command IDs and channel types declared by its
  object remain registered. Removing it also runs `on_unload` and removes its
  optional client API alias.
- A grouped built-in adapter remains until all command IDs and channel types
  associated with that adapter are gone. Its exposed console commands are
  recalculated from the features still present.
- Operator aliases whose manifest commands have disappeared are removed.

## Aliases

YAML UI commands always work under `micro run`. Promote them into the dedicated
`Micro Alias Commands` help section with:

```text
micro alias micro-stdapi-yaml
micro alias micro-stdapi-file-channel
micro alias download getfile
```

The first form aliases a profile, the second an object, and the third one
command under a chosen alias. Aliases are removed automatically when their
required object is unloaded. Alias names must be lowercase command-style names
and cannot replace an active command from another dispatcher.

## Validation and limits

- YAML is loaded with aliases and custom classes disabled.
- Direct UI command names match `[a-z][a-z0-9_]*`; `has`, `help`, `list`, `load`,
  `run`, and `unload` are reserved. Names used by arguments, response fields,
  rows, and extraction entries match the same pattern.
- Duplicate object names, packet command IDs, and channel provider types are
  rejected by Meterpreter. Duplicate UI/helper command names conflict with
  already loaded manifest commands.
- Object loading order is significant; unloading order during rollback is the
  reverse.
- Descriptor ABI, descriptor size, image pointers, handler pointers, duplicate
  commands, duplicate providers, and command/provider tables are validated by
  Meterpreter.
- `commands`, `channels`, and client/UI declarations are configuration claims,
  not a way to import libraries, register arbitrary functions, or grant target
  capabilities.
- The current implementation is Windows-only and ABI v2 objects must be rebuilt
  whenever the ABI changes.

The current validator intentionally has several gaps that manifest authors
should not rely on. It does not reject optional arguments before required ones,
validate default value types, verify format placeholders or table columns,
detect every duplicate name within one UI list, or reject unknown keys outside
`client.helper`. Such manifests can pass initial parsing and fail during client
wiring or command rendering.

See `stdapi/manifests/micro-stdapi.yaml` for standard adapter exposure and
`stdapi/manifests/micro-stdapi-yaml.yaml` for direct YAML UI plus delegated file
channels.
