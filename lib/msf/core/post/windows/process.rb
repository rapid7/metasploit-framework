# -*- coding: binary -*-
require 'msf/core/post/windows/memory'

module Msf
class Post
module Windows

module Process

	include Msf::Post::Windows::Memory

	def execute_shellcode(shellcode, shell_addr)
		inj = inject_shellcode(shellcode, shell_addr)
		if not inj
			vprint_error("Unable to inject shellcode to memory")
			return
		end

		vprint_status("Creating the thread to execute the shellcode...")
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

		return true
	end

	def inject_shellcode(shellcode, shell_addr)
		proc = session.sys.process.open
		addr = allocate_memory(proc, shell_addr, 0x1000)
		if addr.nil?
			vprint_error("Unable to allocate memory")
			return false
		end

		result = proc.memory.write(addr, shellcode)

		return (result.nil?) ? false : true
	end

end # Process
end # Windows
end # Post
end # Msf
