##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'


class Metasploit3 < Msf::Post


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Manage Network Route via Meterpreter Session',
				'Description'   => %q{This module manages session routing via an existing 
					Meterpreter session. It enables other modules to 'pivot' through a 
					compromised host when connecting to the named NETWORK and SUBMASK.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'todb'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter']
			))
		register_options(
			[

				OptString.new('SUBNET', [false, 'Subnet (IPv4, for example, 10.10.10.0)', nil]),
				OptString.new('NETMASK', [false, 'Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"', '255.255.255.0']),
				OptEnum.new('ACTION', [false, 'Specify the action to take.', nil, ['ADD','PRINT',"DELETE"]])

			], self.class)
	end

	# Run Method for when run command is issued
	def run
		print_status("Running module against #{sysinfo['Computer']}")

		case datastore['ACTION']
		when 'PRINT'
			print_routes()
		when 'ADD'
			if validate_cmd(datastore['SUBNET'],netmask)
				print_status("Adding a route to %s/%s..." % [datastore['SUBNET'],netmask])
				add_route(:subnet => datastore['SUBNET'], :netmask => netmask)
			end
		when 'DELETE'
			if datastore['SUBNET']
				print_status("Deleting route to %s/%s..." % [datastore['SUBNET'],netmask])
				delete_route(:subnet => datastore['SUBNET'], :netmask => netmask)
			else
				delete_all_routes()
			end

		end
		
	end

	def delete_all_routes
		if Rex::Socket::SwitchBoard.routes.size > 0
			routes = []
			Rex::Socket::SwitchBoard.each do |route|
				routes << {:subnet => route.subnet, :netmask => route.netmask}
			end
			routes.each {|route_opts| delete_route(route_opts)}

			print_status "Deleted all routes"
		else
			print_status "No routes have been added yet"
		end
	end

	# Identical functionality to command_dispatcher/core.rb, and
	# nearly identical code
	def print_routes
		if Rex::Socket::SwitchBoard.routes.size > 0
			tbl =	Msf::Ui::Console::Table.new(
				Msf::Ui::Console::Table::Style::Default,
				'Header'  => "Active Routing Table",
				'Prefix'  => "\n",
				'Postfix' => "\n",
				'Columns' =>
				  [
					'Subnet',
					'Netmask',
					'Gateway',
				],
				'ColProps' =>
				  {
					'Subnet'  => { 'MaxWidth' => 17 },
					'Netmask' => { 'MaxWidth' => 17 },
				})
			ret = []

			Rex::Socket::SwitchBoard.each { |route|
				if (route.comm.kind_of?(Msf::Session))
					gw = "Session #{route.comm.sid}"
				else
					gw = route.comm.name.split(/::/)[-1]
				end
				tbl << [ route.subnet, route.netmask, gw ]
			}
			print tbl.to_s
		else
			print_status "No routes have been added yet"
		end
	end

	# Yet another IP validator. I'm sure there's some Rex
	# function that can just do this.
	def check_ip(ip=nil)
		return false if(ip.nil? || ip.strip.empty?)
		begin
			rw = Rex::Socket::RangeWalker.new(ip.strip)
			(rw.valid? && rw.length == 1) ? true : false
		rescue
			false
		end
	end

	def cidr_to_netmask(cidr)
		int = cidr.gsub(/\x2f/,"").to_i
		Rex::Socket.addr_ctoa(int)
	end

	def netmask
		case datastore['NETMASK']
		when /^\x2f[0-9]{1,2}/
			cidr_to_netmask(datastore['NETMASK'])
		when /^[0-9]{1,3}\.[0-9]/ # Close enough, if it's wrong it'll fail out later.
			datastore['NETMASK']
		else
			"255.255.255.0"
		end
	end

	# Adds a route to the framework instance
	def add_route(opts={})
		subnet = opts[:subnet]
		Rex::Socket::SwitchBoard.add_route(subnet, netmask, session)
	end

	# Removes a route to the framework instance
	def delete_route(opts={})
		subnet = opts[:subnet]
		Rex::Socket::SwitchBoard.remove_route(subnet, netmask, session)
	end


	# Validates the command options
	def validate_cmd(subnet=nil,netmask=nil)
		if subnet.nil?
			print_error "Missing subnet option"
			return false
		end

		unless(check_ip(subnet))
			print_error "Subnet invalid (must be IPv4)"
			return false
		end

		if(netmask and !(Rex::Socket.addr_atoc(netmask)))
			print_error "Netmask invalid (must define contiguous IP addressing)"
			return false
		end

		if(netmask and !check_ip(netmask))
			print_error "Netmask invalid"
			return false
		end
		true
	end
end
