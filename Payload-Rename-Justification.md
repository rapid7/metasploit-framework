### The Issue
Many payloads perform the same task, yet have different names. This results in confusion and a bad new-user experience. Specifically, ARCH_CMD payloads differ greatly from their shellcode-derived brethren. For example, the most heavily used payload is `windows/meterpreter/reverse_tcp`; the equivalent in ARCH_CMD land is `cmd/unix/reverse`, which gives no indication that the session type will be a shell.

### The Proposal
I propose we rename all the aberrantly-named payloads to match the convention. Specifically:

* cmd/unix/reverse -> cmd/unix/shell_reverse_tcp_telnet
* cmd/unix/reverse_bash -> cmd/unix/shell_reverse_tcp_bash