require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Packet sniffer extension user interface.
#
###
class Console::CommandDispatcher::Railgun

	Klass = Console::CommandDispatcher::Railgun

	include Console::CommandDispatcher

	#
	# Initializes an instance of the railgun command interaction.
	#
	def initialize(shell)
		super
	end

	#
	# List of supported commands.
	#
	def commands
		{
		#	"railgun_test" => "Run a simple railgun_test"
		}
	end

=begin
	def cmd_railgun_test(*args)
		begin
		r = client.railgun.multi([
			["kernel32", "GetLogicalDrives", []]
		])
		rescue ::Exception => e
			p "Error: #{e} #{e.backtrace}"
		end
	end
=end

	def name
		"Railgun"
	end

end

end
end
end
end

