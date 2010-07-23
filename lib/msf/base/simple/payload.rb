require 'msf/base'

module Msf
module Simple

###
#
# Simple payload wrapper class for performing generation.
#
###
module Payload

	include Module

	#
	# Generate a payload with the mad skillz.  The payload can be generated in
	# a number of ways.
	#
	# opts can have:
	#
	#   Encoder     => A encoder module name.
	#   BadChars    => A string of bad characters.
	#   Format      => The format to represent the data as: ruby, perl, c, raw
	#   Options     => A hash of options to set.
	#   OptionStr   => A string of options in VAR=VAL form separated by
	#                  whitespace.
	#   NoComment   => Disables prepention of a comment
	#   NopSledSize => The number of NOPs to use
	#   MaxSize     => The maximum size of the payload.
	#   Iterations  => Number of times to encode.
	#   Force       => Force encoding.
	#
	# raises:
	#
	#   BadcharError => If the supplied encoder fails to encode the payload
	#   NoKeyError => No valid encoder key could be found
	#   ArgumentParseError => Options were supplied improperly
	#
	def self.generate_simple(payload, opts)

		# Import any options we may need
		payload._import_extra_options(opts)
		framework = payload.framework

		# Generate the payload
		e = EncodedPayload.create(payload,
				'BadChars' => opts['BadChars'],
				'MinNops'  => opts['NopSledSize'],
				'Encoder'  => opts['Encoder'],
				'Iterations'  => opts['Iterations'],
				'ForceEncode' => opts['ForceEncode'],
				'Space'    => opts['MaxSize'])

		fmt = opts['Format'] || 'raw'
		inject = opts['KeepTemplateWorking'] || false
		altexe = opts['Template'] || nil

		arch = payload.arch

		# Save off the original payload length
		len = e.encoded.length


		
		case fmt
		when 'exe'
			buf = nil
			if(not arch or (arch.index(ARCH_X86)))
				buf = Msf::Util::EXE.to_win32pe(framework, e.encoded , {:insert => inject, :template => altexe})
			end

			if(arch and (arch.index( ARCH_X86_64 ) or arch.index( ARCH_X64 )))
				buf = Msf::Util::EXE.to_win64pe(framework, e.encoded, {:insert => inject, :template => altexe})
			end

		when 'exe-small'
			buf = nil
			if(not arch or (arch.index(ARCH_X86)))
				buf = Msf::Util::EXE.to_win32pe_old(framework, e.encoded)
			end

		when 'elf'
			buf = Msf::Util::EXE.to_linux_x86_elf(framework, e.encoded)
		when 'macho'
			buf = Msf::Util::EXE.to_osx_x86_macho(framework, e.encoded)
		when 'vba'
			exe = nil
			exe = Msf::Util::EXE.to_win32pe(framework, e.encoded , {:insert => inject, :template => altexe})
			buf = Msf::Util::EXE.to_exe_vba(exe)
		when 'vbs'
			buf = Msf::Util::EXE.to_win32pe_vbs(framework, e.encoded, {:insert => inject, :persist => false, :template => altexe})
		when 'loop-vbs'
			buf = Msf::Util::EXE.to_win32pe_vbs(framework, e.encoded, {:insert => inject, :persist => true, :template => altexe})
		when 'asp'
			buf = Msf::Util::EXE.to_win32pe_asp(framework, e.encoded , {:insert => inject, :persist => false, :template => altexe})
		when 'war'
			plat = Msf::Module::PlatformList.transform(opts['Platform'])

			tmp_plat = plat.platforms
			buf = Msf::Util::EXE.to_jsp_war(framework, arch, tmp_plat, e.encoded, {:persist => false, :template => altexe})
		else
			# Serialize the generated payload to some sort of format
			buf = Buffer.transform(e.encoded, fmt)

			# Prepend a comment
			if (fmt != 'raw' and opts['NoComment'] != true)
				((ou = payload.options.options_used_to_s(payload.datastore)) and ou.length > 0) ? ou += "\n" : ou = ''
				buf = Buffer.comment(
					"#{payload.refname} - #{len} bytes#{payload.staged? ? " (stage 1)" : ""}\n" +
					"http://www.metasploit.com\n" +
					((e.encoder) ? "Encoder: #{e.encoder.refname}\n" : '') +
					((e.nop) ?     "NOP gen: #{e.nop.refname}\n" : '') +
					"#{ou}",
					fmt) + buf

				# If it's multistage, include the second stage too
				if payload.staged?
					stage = payload.generate_stage
	
					# If a stage was generated, then display it
					if stage and stage.length > 0
						buf +=
							"\n" +
							Buffer.comment(
							"#{payload.refname} - #{stage.length} bytes (stage 2)\n" +
							"http://www.metasploit.com\n",
							fmt) + Buffer.transform(stage, fmt)
					end
				end
			end	
		end

		return buf
	end

	#
	# Calls the class method.
	#
	def generate_simple(opts)
		Msf::Simple::Payload.generate_simple(self, opts)
	end

end

end
end
