require 'rex/parser/arguments'

module Msf
module Ui
module Console
module CommandDispatcher

class Nop

	@@generate_opts = Rex::Parser::Arguments.new(
		"-b" => [ true,  "The list of characters to avoid: '\\x00\\xff'" ],
		"-h" => [ false, "Help banner."                                  ],
		"-t" => [ true,  "The output type: ruby, perl, c, or raw."       ])

	include Msf::Ui::Console::ModuleCommandDispatcher

	def commands
		{
			"generate" => "Generates a NOP sled",
		}
	end

	#
	# Generates a NOP sled
	#
	def cmd_generate(args)

		# No arguments?  Tell them how to use it.
		if (args.length == 0)
			args << "-h"
		end

		# Parse the arguments
		badchars = nil
		type     = "ruby"
		length   = 200

		@@generate_opts.parse(args) { |opt, idx, val|
			case opt
				when nil
					length = val.to_i	
				when '-b'
					badchars = Rex::Text.hex_to_raw(val)
				when '-t'
					type = val
				when '-h'
					print(
						"Usage: generate [options] length\n\n" +
						"Generates a NOP sled of a given length.\n" +
						@@generate_opts.usage)
					return false
			end
		}

		# Generate the sled
		begin
			sled = mod.generate_simple(
				length,
				'BadChars' => badchars,
				'Format'   => type)
		rescue
			print_error("Sled generation failed: #{$!}.")
			return false
		end

		# Display generated sled
		print(sled)

		return true
	end

end

end end end end
