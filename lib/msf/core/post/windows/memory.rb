# -*- coding: binary -*-
module Msf
class Post
module Windows

module Memory

	##
	# allocate_memory(proc, base_address, length)
	#
	# Summary:
	#   Allocates a memory to a given process
	#
	# Parameters:
	#   proc         - The process to allocate the memory to
	#   base_address - The memory address to write to in the process
	#   length       - Region size
	#
	# Returns:
	#   A Fixnum value of the memory address. nil if the alloc failed.
	#   
	##
	def allocate_memory(proc, base_address, length)
		result = session.railgun.ntdll.NtAllocateVirtualMemory(
			-1,                                      # Process Handle
			[ base_address ].pack("V"),              # Base Address
			nil,                                     # Zero Bits
			[ length ].pack("V"),                    # Region Size
			"MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN",   # Allocation Type
			"PAGE_EXECUTE_READWRITE"                 # Protect
		)

		if not result["BaseAddress"] or result["BaseAddress"].empty?
			vprint_error("Cannot allocate memory without a base address")
			return nil
		end

		my_address = result["BaseAddress"].unpack("V")[0]

		vprint_status("Memory allocated at 0x#{my_address.to_s(16)}")

		if not proc.memory.writable?(my_address)
			vprint_error("Not writable: 0x#{my_address.to_s(16)}")
			return nil
		end

		my_address
	end

end # Memory
end # Windows
end # Post
end # Msf
