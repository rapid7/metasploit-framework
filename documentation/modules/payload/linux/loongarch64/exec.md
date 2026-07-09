## Vulnerable Application

This payload targets Linux systems running on the LoongArch64 architecture. It uses the
`execve` syscall (syscall number 221) to execute an arbitrary command via `/bin/sh -c`,
then the process exits.

It is suitable for use in exploits targeting LoongArch64 Linux systems where arbitrary
code execution has been achieved.

## Verification Steps

1. Generate the payload as an ELF executable:

```
./msfvenom -p linux/loongarch64/exec CMD=id -f elf -o exec.elf
chmod +x exec.elf
```

2. Run it under QEMU user-mode emulation:

```
qemu-loongarch64 ./exec.elf
```

3. Confirm the command was executed:

```
uid=1000(user) gid=1000(user) groups=1000(user)
```

## Options

### CMD

The command string to execute on the target system. This is passed to `/bin/sh -c`.

## Scenarios

### LoongArch64 Linux — executing a command

This scenario demonstrates using the payload to execute an arbitrary command after gaining
code execution on a LoongArch64 Linux target.

#### Version and OS: LoongArch64 Linux (tested with qemu-loongarch64)

Generate the payload:

```
msf6 > use payload/linux/loongarch64/exec
msf6 payload(linux/loongarch64/exec) > set CMD id
CMD => id
msf6 payload(linux/loongarch64/exec) > generate -f elf -o /tmp/exec.elf
[*] Writing 204 bytes to /tmp/exec.elf...
```

Run on target (or via QEMU for testing):

```
$ qemu-loongarch64 /tmp/exec.elf
uid=1000(user) gid=1000(user) groups=1000(user)
```
