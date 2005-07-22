require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Net
# ---
#
# The networking portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Net

	Klass = Console::CommandDispatcher::Stdapi::Net

	include Console::CommandDispatcher

	#
	# Options for the generate command
	#
	@@route_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help banner." ])

	#
	# List of supported commands
	#
	def commands
		{
			"ipconfig" => "Display interfaces",
			"route"    => "View and modify the routing table",
		}
	end

	#
	# Name for this dispatcher
	#
	def name
		"Stdapi: Networking"
	end

	#
	# Displays interfaces on the remote machine.
	#
	def cmd_ipconfig(*args)
		ifaces = client.net.config.interfaces

		if (ifaces.length == 0)
			print_line("No interfaces were found.")
		else
			client.net.config.each_interface { |iface|
				print("\n" + iface.pretty + "\n")	
			}
		end
	end

	#
	# Displays or modifies the routing table on the remote machine.
	#
	def cmd_route(*args)
		# Default to list
		if (args.length == 0)
			args.unshift("list")
		end

		# Check to see if they specified -h
		@@route_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print(
						"Usage: route [-h] command [args]\n\n" +
						"Display or modify the routing table on the remote machine.\n\n" +
						"Supported commands:\n\n" +
						"   add    [subnet] [netmask] [gateway]\n" +
						"   delete [subnet] [netmask] [gateway]\n" +
						"   list\n\n")
					return true
			end
		}

		# Process the commands
		case args.shift
			when "list"
				routes = client.net.config.routes

				if (routes.length == 0)
					print_line("No routes were found.")
				else
					tbl = Rex::Ui::Text::Table.new(
						'Header'  => "Network routes",
						'Indent'  => 4,
						'Columns' => 
							[
								"Subnet",
								"Netmask",
								"Gateway"
							])

					routes.each { |route|
						tbl << [ route.subnet, route.netmask, route.gateway ]	
					}

					print("\n" + tbl.to_s + "\n")
				end
			when "add"
				print_line("Creating route #{args[0]}/#{args[1]} -> #{args[2]}")

				client.net.config.add_route(*args)
			when "delete"
				print_line("Deleting route #{args[0]}/#{args[1]} -> #{args[2]}")

				client.net.config.remove_route(*args)
			else
				print_error("Unsupported command: #{args[0]}")
		end
	end

end

end
end
end
end
