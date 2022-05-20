Metasploit includes a library for leveraging .NET deserialization attacks. Using
it within a module is very straight forward, the module author just needs to
know two things: the gadget chain and the formatter. The library uses the same
names for each of these values as the [YSoSerial.NET][1] project for
compatibility, although the Metasploit library only supports a subset of the
functionality.

## Support Matrix

The following table outlines the supported gadget chains, formatters and the
compatibility of each.

| Gadget Chain Name           | BinaryFormatter | LosFormatter | SoapFormatter |
| --------------------------- | --------------- | ------------ | ------------- |
| ClaimsPrincipal             | Yes             | Yes          | Yes           | 
| TextFormattingRunProperties | Yes             | Yes          | Yes           |
| TypeConfuseDelegate         | Yes             | Yes          | No            |
| WindowsIdentity             | Yes             | Yes          | Yes           |

## Basic Usage

The library is located in `Msf::Util::DotNetDeserialization` and contains the
following methods which are intended for use by module authors.

* `#generate(cmd, gadget_chain:, formatter:)`

    This function will generate a serialized payload to execute the specified
    operating system command *cmd*. The command is serialized using the
    specified *gadget_chain* and formatted with the specified *formatter*. The
    *gadget_chain* and *formatter* options will be specific to the vulnerability
    that is being executed. This functions returns a string.

* `#generate_formatted(stream, formatter:)`

    Format a `SerializedStream` object, as created by `#generate_gadget_chain`.
    The *stream* will be formatted using the specified *formatter* and returned
    as a string.

* `#generate_gadget_chain(cmd, gadget_chain:)`

    Create a gadget chain to run the specified operating system command *cmd*.
    This returns a `SerializedStream` object which can be inspected and modified
    but must formatted (using `#generate_formatted`) before it is useful.

`#generate` is the primary function and is functionally equivalent to the
following. In the future the `#generate_*` functions may contain additional
options specific to their respective chain or formatter.

```ruby
stream = generate_gadget_chain(cmd, gadget_chain)
formatted = generate_formatted(stream, formatter)
```

### Example Usage

The following example uses the `TextFormattingRunProperties` gadget chain
formatted with the `LosFormatter`.

```ruby
serialized = ::Msf::Util::DotNetDeserialization.generate(
 cmd,  # this is the Operating System command to run
 gadget_chain: :TextFormattingRunProperties,
 formatter: :LosFormatter
)
```

## Command Line Tool

The library also has an interface available as a standalone command line tool
which is suitable for creating payloads for single-use research purposes. This
tool `dot_net.rb` is available in the `tools/payloads/ysoserial` directory. The
arguments for this tool are aligned with those of [YSoSerial.NET][1], allowing
the arguments of basic invocations to be the same. It should be noted however
that the [supported](#support-matrix) gadgets and formatters are not the same.

Help output:

```
Usage: ./dot_net.rb [options]

Generate a .NET deserialization payload that will execute an operating system
command using the specified gadget chain and formatter.

Available formatters:
   * BinaryFormatter
   * LosFormatter
   * SoapFormatter

Available gadget chains:
   * TextFormattingRunProperties
   * TypeConfuseDelegate
   * WindowsIdentity

Example: ./dot_net.rb -c "net user msf msf /ADD" -f BinaryFormatter -g TextFormattingRunProperties

Specific options:
   -c, --command   <String>         The command to run
   -f, --formatter <String>         The formatter to use (default: BinaryFormatter)
   -g, --gadget    <String>         The gadget chain to use (default: TextFormattingRunProperties)
   -o, --output    <String>         The output format to use (default: raw, see: --list-output-formats)
       --list-output-formats        List available output formats, for use with --output
   -h, --help                       Show this message
```

The `-g` / `--gadget` option maps to the *gadget_chain* argument for the
generate functions while the `-f` / `--formatter` arguments maps to the
*formatter* argument.

## Making Changes

Adding new gadget chains and formatters involves creating a new file in the
respective library directory: [`lib/msf/util/dot_net_deserialization`][2]. The
"native" gadget chain type is implemented following the [MS-NRBF][3] format and
the [Bindata][4] records as defined in [`types/`][5] subdirectory. Once the new
gadget chain or formatter is implemented, it needs to be added to the main
library file ([`dot_net_deserialization.rb`][6]).

Since serialization chain generate is deterministic, a [unit test][7] should be
added for any new gadget chain to ensure that the checksum of the
BinaryFormatter representation is consistent.

## Further Reading
Since the .NET deserialization gadgets run operating system commands, the
following resources can be helpful for module developers to deliver native
payloads such as Meterpreter.

* [How to use command stagers][8]
* [How to use Powershell in an exploit][9]

[1]: https://github.com/pwntester/ysoserial.net
[2]: https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/util/dot_net_deserialization
[3]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/75b9fe09-be15-475f-85b8-ae7b7558cfe5
[4]: https://github.com/dmendel/bindata
[5]: https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/util/dot_net_deserialization/types
[6]: https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/util/dot_net_deserialization.rb
[7]: https://github.com/rapid7/metasploit-framework/blob/master/spec/lib/msf/util/dot_net_deserialization_spec.rb
[8]: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-command-stagers
[9]: https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Powershell-in-an-exploit