# -*- coding: binary -*-
require 'rex/post/meterpreter'


module Rex
module Post
module Meterpreter
module Ui

class Console::CommandDispatcher::Android::Root

	Klass = Console::CommandDispatcher::Android::Root
	include Console::CommandDispatcher
	include Msf::Auxiliary::Report

	def initialize(shell)
		super
	end

	def commands 
		all = {
			"device_shutdown"   => "Shutdown device",
		}

		reqs = {
			"device_shutdown" => [ "device_shutdown"],
		}

		all.delete_if do |cmd, desc|
			del = false
			reqs[cmd].each do |req|
				next if client.commands.include? req
				del = true
				break
			end

			del
		end

		all
	end


	def cmd_device_shutdown(*args)

    nSeconds = 0
		device_shutdown_opts = Rex::Parser::Arguments.new(
			"-h" => [ false, "Help Banner" ],
			"-t" => [ false, "Shutdown after n seconds"]		
			)

		device_shutdown_opts.parse( args ) { | opt, idx, val |
			case opt
				when "-h"
					print_line( "Usage: device_shutdown [options]\n" )
					print_line( "Shutdown device." )
					print_line( device_shutdown_opts.usage )
					return
				when "-t"
					nSeconds = val
			end
		}

		res = client.root.device_shutdown(nSeconds)
    
    if res == true
      print_line("[*] Device will shutdown #{nSeconds > 0 ?("after " + nSeconds + "seconds"):"now"}")
    else
      print_line("[x] Device will shutdown failed")
		end
  end

  def name
		"Android: Rooted"
	end

end

end
end
end
end
