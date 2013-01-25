require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Sample command dispatcher
#
###
class Console::CommandDispatcher::Sample

	Klass = Console::CommandDispatcher::Sample

	include Console::CommandDispatcher

	#
	# Initializes an instance of the priv command interaction.
	#
	def initialize(shell)
		super
	end

	#
	# List of supported commands.
	#
	def commands
		{
			"ping" => "ping meterpreter",		
		}
	end
	
	@@ping_opts = Rex::Parser::Arguments.new(
		"-p" => [ true,  "Ping payload" ])

	

	def cmd_ping(*args)
		payload="HELLO WORLD!"

		@@ping_opts.parse(args) { |opt, idx, val|
			case opt
				when "-p"
					payload = val
			end
		}
				
		

		p=client.sample.sample_ping(payload)
		print "Reply from server: #{p}\n"

		return true
	end

	#
	# Name for this dispatcher
	#
	def name
		"Sample"
	end

end

end
end
end
end
