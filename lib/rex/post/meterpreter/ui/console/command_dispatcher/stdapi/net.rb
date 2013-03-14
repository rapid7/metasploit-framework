# -*- coding: binary -*-
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
		all = {
			"ipconfig" => "Display interfaces",
			"ifconfig" => "Display interfaces",
			"route"    => "View and modify the routing table",
			"portfwd"  => "Forward a local port to a remote service",
			"arp"      => "Display the host ARP cache",
			"netstat"  => "Display the network connections",
		}
		reqs = {
			"ipconfig" => [ "stdapi_net_config_get_interfaces" ],
			"ifconfig" => [ "stdapi_net_config_get_interfaces" ],
			"route"    => [
				# Also uses these, but we don't want to be unable to list them
				# just because we can't alter them.
				#"stdapi_net_config_add_route",
				#"stdapi_net_config_remove_route",
				"stdapi_net_config_get_routes"
			],
			# Only creates tcp channels, which is something whose availability
			# we can't check directly at the moment.
			"portfwd"  => [ ],
			"arp"      => [ "stdapi_net_config_get_arp_table" ],
			"netstat"  => [ "stdapi_net_config_get_netstat" ],
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

	#
	# Name for this dispatcher.
	#
	def name
		"Stdapi: Networking"
	end
	#
	# Displays network connections of the remote machine.
	#
	def cmd_netstat(*args)
		connection_table = client.net.config.netstat
		tbl = Rex::Ui::Text::Table.new(
		'Header'  => "Connection list",
		'Indent'  => 4,
		'Columns' =>
			[
				"Proto",
				"Local address",
				"Remote address",
				"State",
				"User",
				"Inode",
				"PID/Program name"
			])

		connection_table.each { |connection|
			tbl << [ connection.protocol, connection.local_addr_str, connection.remote_addr_str,
				connection.state, connection.uid, connection.inode, connection.pid_name]
		}

		if tbl.rows.length > 0
			print("\n" + tbl.to_s + "\n")
		else
			print_line("Connection list is empty.")
		end
	end

	#
	# Displays ARP cache of the remote machine.
	#
	def cmd_arp(*args)
		arp_table = client.net.config.arp_table
		tbl = Rex::Ui::Text::Table.new(
		'Header'  => "ARP cache",
		'Indent'  => 4,
		'Columns' =>
			[
				"IP address",
				"MAC address",
				"Interface"
			])

		arp_table.each { |arp|
			tbl << [ arp.ip_addr, arp.mac_addr, arp.interface ]
		}

		if tbl.rows.length > 0
			print("\n" + tbl.to_s + "\n")
		else
			print_line("ARP cache is empty.")
		end
	end


	#
	# Displays interfaces on the remote machine.
	#
	def cmd_ipconfig(*args)
		ifaces = client.net.config.interfaces

		if (ifaces.length == 0)
			print_line("No interfaces were found.")
		else
			ifaces.sort{|a,b| a.index <=> b.index}.each do |iface|
				print("\n" + iface.pretty + "\n")
			end
		end
	end

	alias :cmd_ifconfig :cmd_ipconfig

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

				# IPv4
				tbl = Rex::Ui::Text::Table.new(
					'Header'  => "IPv4 network routes",
					'Indent'  => 4,
					'Columns' =>
						[
							"Subnet",
							"Netmask",
							"Gateway",
							"Metric",
							"Interface"
						])

				routes.select {|route|
					Rex::Socket.is_ipv4?(route.netmask)
				}.each { |route|
					tbl << [ route.subnet, route.netmask, route.gateway, route.metric, route.interface ]
				}

				if tbl.rows.length > 0
					print("\n" + tbl.to_s + "\n")
				else
					print_line("No IPv4 routes were found.")
				end

				# IPv6
				tbl = Rex::Ui::Text::Table.new(
					'Header'  => "IPv6 network routes",
					'Indent'  => 4,
					'Columns' =>
						[
							"Subnet",
							"Netmask",
							"Gateway",
							"Metric",
							"Interface"
						])

				routes.select {|route|
					Rex::Socket.is_ipv6?(route.netmask)
				}.each { |route|
					tbl << [ route.subnet, route.netmask, route.gateway, route.metric, route.interface ]
				}

				if tbl.rows.length > 0
					print("\n" + tbl.to_s + "\n")
				else
					print_line("No IPv6 routes were found.")
				end

			when "add"
                        	# Satisfy check to see that formatting is correct
                                unless Rex::Socket::RangeWalker.new(args[0]).length == 1
                                        print_error "Invalid IP Address"
                                        return false
                                end

                                unless Rex::Socket::RangeWalker.new(args[1]).length == 1
                                        print_error "Invalid Subnet mask"
                                        return false
                                end

				print_line("Creating route #{args[0]}/#{args[1]} -> #{args[2]}")

				client.net.config.add_route(*args)
			when "delete"
			        # Satisfy check to see that formatting is correct
                                unless Rex::Socket::RangeWalker.new(args[0]).length == 1
                                        print_error "Invalid IP Address"
                                        return false
                                end

                                unless Rex::Socket::RangeWalker.new(args[1]).length == 1
                                        print_error "Invalid Subnet mask"
                                        return false
                                end

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
					cmd_portfwd_help
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

			when "flush"

				counter = 0
				service.each_tcp_relay do |lhost, lport, rhost, rport, opts|
					next if (opts['MeterpreterRelay'] == nil)

					if (service.stop_tcp_relay(lport, lhost))
						print_status("Successfully stopped TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
					else
						print_error("Failed to stop TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
						next
					end

					counter += 1
				end
				print_status("Successfully flushed #{counter} rules")

			else
				cmd_portfwd_help
		end
	end

	def cmd_portfwd_help
		print_line "Usage: portfwd [-h] [add | delete | list | flush] [args]"
		print_line
		print @@portfwd_opts.usage
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
				'Proto'    => 'tcp'
			)
		)
	end

end

end
end
end
end

