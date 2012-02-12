require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Mirv command dispatcher
#
###
class Console::CommandDispatcher::Mirv

	Klass = Console::CommandDispatcher::Mirv

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
			"luado" => "Do lua code",		
		}
	end
	
#	@@luado_opts = Rex::Parser::Arguments.new(
#		"-c" => [ true,  "Lua code, if blank, returns Lua version" ])

	

	def cmd_luado(*args)
		if args.length then
			payload=args.join(" ")
		else
			payload="return _VERSION"
		end
		if not payload.start_with? "return" then
			payload = "return " + payload
		end
		#print "Sending #{payload}\n for execution by Lua"		
				
		

		p=client.Mirv.mirv_luado(payload)
		print p+"\n"

		return true
	end

	#
	# Name for this dispatcher
	#
	def name
		"Mirv"
	end

end

end
end
end
end
