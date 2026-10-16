# Meterpreter YAML Aliases

The `meterpreter_aliases` plugin adds client-side commands to Meterpreter consoles from a versioned YAML configuration. Each alias invokes a post module or local exploit with structured options; it does not execute Ruby or expand an arbitrary shell command.

## Loading

Load the bundled aliases:

```text
msf > load meterpreter_aliases
```

Load a custom alias file instead:

```text
msf > load meterpreter_aliases Config=/absolute/path/to/aliases.yml
```

The plugin attaches aliases to existing Meterpreter sessions and sessions opened after the plugin is loaded. Use `meterpreter_aliases` in the framework console or `aliases` in a Meterpreter console to list configured commands. Use `meterpreter_aliases_reload` or `aliases_reload` after editing the active YAML file.

A reload is atomic. Invalid YAML or an unavailable module leaves the previous configuration active.

## Configuration

The top-level schema has a version and an alias map:

```yaml
version: 1
aliases:
  example:
    description: Run an example module
    platforms: [linux]
    module: post/linux/gather/enum_system
    positional:
      - option: TARGET_PATH
        required: true
    defaults:
      VERBOSE: false
    switches:
      "-x":
        description: Enable an optional behavior
        options:
          EXECUTE: true
```

Alias names must contain lowercase letters, numbers, dashes, and underscores and must begin with a letter. `aliases` and `aliases_reload` are reserved. Modules must exist and must be post modules or local exploits. Positional arguments are applied in order to the named module options. Required positional arguments must precede optional ones.

Each configured switch sets one or more module options. Switches are single-letter flags such as `-x`; `-h` is supplied automatically. Option values must be strings, integers, booleans, or null.

## Architecture Options

An alias can derive module options from the operating-system architecture returned by embedded Linux `stdapi`:

```yaml
architecture_options:
  source: sysinfo
  values:
    x64:
      TARGET: 0
      PAYLOAD: linux/x64/meterpreter/reverse_tcp
    aarch64:
      TARGET: 2
      PAYLOAD: linux/aarch64/meterpreter/reverse_tcp
```

Defaults are applied first, followed by architecture options, selected switch options, and positional values. Later values override earlier values. Handler options such as `LHOST` are inherited from the exploit that opened the current session.

## Bundled Backdoor Alias

The bundled configuration provides:

```text
meterpreter > backdoor <remote ELF path>
meterpreter > backdoor <remote ELF path> -x
```

The alias selects the Linux x86, x64, or AArch64 staged Meterpreter payload from `sysinfo`. `-x` enables `PrependExecOnce` and the required Linux kernel compatibility setting.

## Bundled Execute-Assembly Alias

On Windows Meterpreter sessions, the bundled configuration provides:

```text
meterpreter > execute-assembly <local assembly path> ["assembly arguments"]
```

The alias invokes `post/windows/manage/execute_dotnet_assembly`. The assembly path is local to Metasploit. Pass command-line arguments as one quoted value when the assembly requires them.

## Bundled Persistence Suggester Alias

The bundled `enum_persistence` alias invokes `post/multi/recon/persistence_suggester` for the current Linux, Windows, or macOS Meterpreter session:

```text
meterpreter > enum_persistence
```
