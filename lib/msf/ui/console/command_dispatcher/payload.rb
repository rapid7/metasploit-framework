require 'rex/parser/arguments'

module Msf
module Ui
module Console
module CommandDispatcher

class Payload

	@@generate_opts = Rex::Parser::Arguments.new(
		"-b" => [ true,  "The list of characters to avoid '\\x00\\xff'"         ],
		"-t" => [ true,  "The output type: ruby, perl, c, or raw."              ],
		"-e" => [ true,  "The name of the encoder module to use."               ],
		"-o" => [ true,  "A space separated list of options in VAR=VAL format." ],
		"-h" => [ false, "Help banner."                                         ])

	include Msf::Ui::Console::ModuleCommandDispatcher

	def commands
		return {
				"generate" => "Generates a payload",	
			}
	end

	#
	# Generates a payload
	#
	def cmd_generate(args)

		# Parse the arguments
		encoder_name = nil
		option_str   = nil
		badchars     = nil
		encoder      = nil
		type         = "ruby"

		@@generate_opts.parse(args) { |opt, idx, val|
			case opt
				when '-b'
					badchars = [ val.downcase.gsub(/\\x([a-f0-9][a-f0-9])/, '\1') ].pack("H*")
				when '-t'
					type = val
				when '-e'
					encoder_name = val
				when '-o'
					option_str = val
				when '-h'
					print(
						"Usage: generate [options]\n\n" +
						"Generates a payload.\n" +
						@@generate_opts.usage)
					return true
			end
		}

		# If an encoder name was specified, try to instantiate it 
		if ((encoder_name) and
		    (encoder = framework.modules.create(encoder_name)) == nil)
			print_error("Invalid encoder specified: #{encoder_name}")
			return false
		end

		# Generate the payload
		begin
			buf = Msf::Simple::Payload.generate(
				mod, 
				'Badchars'  => badchars,
				'Encoder'   => encoder,
				'Format'    => type,
				'OptionStr' => option_str)
		rescue
			print_error("Payload generation failed: #{$!}")
			return false
		end

		# Display generated payload
		print(buf)

		return true

	end

end

end end end end
