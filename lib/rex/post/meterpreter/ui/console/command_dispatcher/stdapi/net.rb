require 'rex/post/meterpreter'
require 'rex/service_manager'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The networking portion of the standard API extension.
#
###
class Console::CommandDispatcher::Stdapi::Net

	Klass = Console::CommandDispatcher::Stdapi::Net

	include Console::CommandDispatcher

	#
	# This module is used to extend the meterpreter session
	# so that local port forwards can be tracked and cleaned
	# up when the meterpreter session goes away
	#
	module PortForwardTracker
		def cleanup
			super

			if pfservice
				pfservice.deref
			end
		end

		attr_accessor :pfservice
	end

	#
	# Options for the route command.
	#
	@@route_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help banner." ])

	#
	# Options for the portfwd command.
	#
	@@portfwd_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help banner." ],
		"-l" => [ true,  "The local port to listen on." ],
		"-r" => [ true,  "The remote host to connect to." ],
		"-p" => [ true,  "The remote port to connect to." ],
		"-L" => [ true,  "The local host to listen on (optional)." ])

	#
	# List of supported commands.
	#
	def commands
		{
			"ipconfig" => "Display interfaces",
			"route"    => "View and modify the routing table",
			"portfwd"  => "Forward a local port to a remote service",
		}
	end

	#
	# Name for this dispatcher.
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

		cmd = args.shift

		# Process the commands
		case cmd
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
				print_error("Unsupported command: #{cmd}")
		end
	end

	#
	# Starts and stops local port forwards to remote hosts on the target
	# network.  This provides an elementary pivoting interface.
	#
	def cmd_portfwd(*args)
		args.unshift("list") if args.empty?

		# For clarity's sake.
		lport = nil
		lhost = nil
		rport = nil
		rhost = nil

		# Parse the options
		@@portfwd_opts.parse(args) { |opt, idx, val|
			case opt
				when "-h"
					print(
						"Usage: portfwd [-h] [add / delete / list] [args]\n\n" +
						@@portfwd_opts.usage)
					return true
				when "-l"
					lport = val.to_i
				when "-L"
					lhost = val
				when "-p"
					rport = val.to_i
				when "-r"
					rhost = val
			end
		}

		# If we haven't extended the session, then do it now since we'll
		# need to track port forwards
		if client.kind_of?(PortForwardTracker) == false
			client.extend(PortForwardTracker)
			client.pfservice = Rex::ServiceManager.start(Rex::Services::LocalRelay)
		end

		# Build a local port forward in association with the channel
		service = client.pfservice

		# Process the command
		case args.shift
			when "list"

				cnt = 0

				# Enumerate each TCP relay
				service.each_tcp_relay { |lhost, lport, rhost, rport, opts|
					next if (opts['MeterpreterRelay'] == nil)

					print_line("#{cnt}: #{lhost}:#{lport} -> #{rhost}:#{rport}")

					cnt += 1
				}

				print_line
				print_line("#{cnt} total local port forwards.")

				
			when "add"

				# Validate parameters
				if (!lport or !rhost or !rport)
					print_error("You must supply a local port, remote host, and remote port.")
					return
				end

				# Start the local TCP relay in association with this stream
				service.start_tcp_relay(lport, 
					'LocalHost'         => lhost,
					'PeerHost'          => rhost,
					'PeerPort'          => rport,
					'MeterpreterRelay'  => true,
					'OnLocalConnection' => Proc.new { |relay, lfd|
						create_tcp_channel(relay)
						})

				print_status("Local TCP relay created: #{lhost || '0.0.0.0'}:#{lport} <-> #{rhost}:#{rport}")

			# Delete local port forwards
			when "delete"

				# No local port, no love.
				if (!lport)
					print_error("You must supply a local port.")
					return
				end

				# Stop the service
				if (service.stop_tcp_relay(lport, lhost))
					print_status("Successfully stopped TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
				else
					print_error("Failed to stop TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
				end

		end
	end

protected

	#
	# Creates a TCP channel using the supplied relay context.
	#
	def create_tcp_channel(relay)
		client.net.socket.create(
			Rex::Socket::Parameters.new(
				'PeerHost' => relay.opts['PeerHost'],
				'PeerPort' => relay.opts['PeerPort'],
				'Proto'    => 'tcp'))
	end

end

end
end
end
end
