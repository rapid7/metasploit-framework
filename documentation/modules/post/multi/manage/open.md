This module allows you to open arbitrary files or URLs on the target system.

## Vulnerable Application

The following platforms are supported:


* Windows
* Linux
* OS X

## Verification Steps

1. Obtain a session.
2. In msfconsole do `use post/multi/open`.
3. Set the `SESSION` option.
4. Set the `URI` to the URI you want to use (ex: `https://metasploit.com` or `file://mouhaha.txt`).
5. Do `run`.

## Options

**URI**

The URI that should be passed to the opening command, can be a webiste or a file.
