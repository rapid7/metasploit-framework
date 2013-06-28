# -*- coding: binary -*-
module Msf
class Post
module Windows

module Process

	def execute_shellcode(shell_addr)
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

end # Process
end # Windows
end # Post
end # Msf
