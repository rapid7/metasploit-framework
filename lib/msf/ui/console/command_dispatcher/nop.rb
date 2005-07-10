require 'rex/parser/arguments'

module Msf
module Ui
module Console
module CommandDispatcher

class Nop

	@@generate_opts = Rex::Parser::Arguments.new(
		"-b" => [ true,  "The list of characters to avoid: '\\x00\\xff'" ],
		"-t" => [ true,  "The output type: ruby, perl, c, or raw."       ],
		"-h" => [ false, "Help banner."                                  ])

	include Msf::Ui::Console::ModuleCommandDispatcher

	def commands
		return {
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
					badchars = [ val.downcase.gsub(/\\x([a-f0-9][a-f0-9])/, '\1') ].pack("H*")
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
			sled = Msf::Simple::Nop.generate(
				mod, 
				length,
				'Badchars' => badchars,
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
