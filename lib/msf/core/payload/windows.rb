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
	# ROR hash associations for some of the exit technique routines
	#
	@@exit_types = 
		{
			'seh'     => 0x5f048af0, # SetUnhandledExceptionFilter
			'thread'  => 0x60e0ceef, # ExitThread
			'process' => 0x73e2d87e, # ExitProcess
		}

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

end
