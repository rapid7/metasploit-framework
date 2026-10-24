# Meterpreter Microextensions

Meterpreter microextensions are small Common Object File Format (COFF) objects
loaded into a running native Windows Meterpreter. A resident object can register
one or more canonical Meterpreter packet commands or named channel providers.
This allows an operator to add a focused capability without loading a complete
Meterpreter extension.

Microextensions are not Metasploit modules, payloads, or one-shot Beacon Object
Files (BOFs). Their handlers remain available until the object is unloaded or
the Meterpreter process exits. The `micro` command manages their complete
lifecycle from a Meterpreter console.

The source under `data/meterpreter/microextensions/examples` demonstrates the
integration. It is reference material for developers and is not supported
target-side code intended to be used as-is.

## Requirements and limitations

- A native Windows x86 or x64 Meterpreter implementing the `core_micro_*`
  command family is required. The `micro` console command is hidden when the
  session does not advertise that command family.
- An object must match the session architecture and the Meterpreter
  microextension ABI used to build it.
- The current manifest implementation accepts `platform: windows` and the
  `x86` and `x64` architectures.
- Loading native code into Meterpreter is not isolated. A bug in an object's
  initializer, handler, channel provider, or cleanup routine can terminate or
  corrupt the Meterpreter process.
- Conventional extensions and a microextension cannot own the same client
  adapter at the same time. Test compatibility profiles in a fresh session
  without automatically loading `stdapi`.

Treat COFF objects, manifests, and Ruby client helpers as trusted code. Objects
execute in the Meterpreter process on the target. Helper source executes in the
`msfconsole` process with the operator's local permissions.

## Console command reference

### Load one object

```text
micro load <name> <object.o>
```

Framework validates the COFF machine type before sending it to Meterpreter.
Meterpreter returns a handle and the registered command and channel inventory.
Direct object loading does not install a manifest-provided client adapter or UI.

### Load a manifest profile

```text
micro load <manifest.yaml>
```

A `meterpreter-micro/v1` manifest declares the ordered objects in a profile,
their expected command IDs and channel providers, and their Framework-side
presentation. Relative paths are resolved from the manifest's directory.

Framework checks each remote object's returned features against the manifest.
When an object, helper, or adapter fails to initialize, objects loaded earlier
in that operation are unloaded in reverse order.

### Query and enumerate

```text
micro has <command-id|command-name> [...]
micro list
```

`micro has` asks the remote loader which requested command IDs are owned by
resident microextensions. `micro list` reports each object's name, handle, ABI,
commands, and channel providers. Conventional extension commands have a
separate inventory.

### Run manifest commands

```text
micro run <manifest-command> [arguments]
```

Manifest commands can create and render a simple Meterpreter packet directly,
delegate complex behavior to an existing Framework adapter, or invoke a Ruby
helper packaged beside the manifest.

### Create command aliases

```text
micro alias
micro alias <profile|object|command> [alias]
```

Without arguments, `micro alias` lists active aliases. A profile or object
scope promotes all of its manifest commands into their own Meterpreter help
section. A command scope optionally selects a different alias. Aliases cannot
replace an active command and are removed when their required remote feature is
unloaded.

### Unload an object

```text
micro unload <name|handle>
```

Unloading deregisters the object's packet commands and channel providers. The
Framework command inventory, adapters, helpers, and aliases are then updated to
match the remote inventory. An object that owns a currently open channel may
reject the unload operation as busy.

## Building the examples

The examples use Meterpreter's internal `MetApi` layout and must be compiled
against a compatible `metasploit-payloads` checkout. They require the MinGW x86
and x64 cross-compilers, `nm`, and `objdump`. No compiled object files are
stored in the Framework repository.

From the Framework repository root:

```sh
cd data/meterpreter/microextensions/examples
make PAYLOADS=/absolute/path/to/metasploit-payloads
make PAYLOADS=/absolute/path/to/metasploit-payloads verify
```

`make verify` checks the expected PE/COFF architecture, exported entry points,
and absence of unresolved external symbols. Generated files are written to the
ignored `build` directory.

Every object exports `micro_init` and `micro_deinit`. `micro_init` returns its
ABI version, unique object name, command table, and channel-provider table.
Objects are deliberately organized into dependency islands so a profile can
load and unload only the capability it needs.

See
`data/meterpreter/microextensions/examples/docs/manifest.md` for the complete
manifest schema and client adapter, YAML UI, delegate, helper, alias, and
validation reference.

## Trying the minimal YAML example

Build and install a compatible Meterpreter, then open a fresh native Windows
Meterpreter session. To exercise a micro-only session, configure the payload
with `AutoLoadExtensions []`, `AutoLoadStdapi false`, and `AutoSystemInfo
false`.

Run these commands from an `msfconsole` process whose working directory is the
Framework root:

```text
micro load ./data/meterpreter/microextensions/examples/custom/manifests/micro-yaml-ui.yaml
micro list
micro has echo
micro run echo "hello from yaml"
micro alias echo
echo "hello through an alias"
micro unload micro-yaml-echo
micro list
```

The two echo requests should return the supplied string. After unload, the
inventory should be empty and the alias should no longer be available.

## Trying the compatibility profile

The larger `micro-stdapi` reference profile demonstrates canonical command IDs,
native pool channels, existing Framework client adapters, and compatibility
with post modules that declare only the commands they use:

```text
micro load ./data/meterpreter/microextensions/examples/stdapi/manifests/micro-stdapi-yaml.yaml
micro alias micro-stdapi-yaml
micro run sysinfo
micro run ls C:/Windows
micro run download C:/Windows/win.ini ./win.ini
run post/windows/gather/forensics/enum_drives MAXDRIVES=0
```

Use this profile as an integration example, not as a replacement for the
supported `stdapi` extension.

## Developing another example

1. Choose one focused feature and place it in its own object. Reuse canonical
   Meterpreter command IDs when the packet and API contracts are compatible.
2. Define the object and its exact command/channel inventory in a
   `meterpreter-micro/v1` manifest.
3. Use a built-in client adapter for existing APIs. Prefer the YAML UI for
   straightforward request/response commands and a helper only for controller
   behavior that needs Ruby.
4. Build both supported architectures and run `make verify`.
5. Test load, use, busy-channel behavior where applicable, unload, and a second
   load in the same session.
