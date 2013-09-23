#
# Meterpreter script for setting up a route from within a
# Meterpreter session, without having to background the
# current session.

# Default options
session = client
subnet = nil
netmask = "255.255.255.0"
print_only = false
remove_route = false
remove_all_routes = false

# Options parsing
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [false, "Help and usage"],
	"-s" => [true, "Subnet (IPv4, for example, 10.10.10.0)"],
	"-n" => [true, "Netmask (IPv4, for example, 255.255.255.0"],
	"-p" => [false, "Print active routing table. All other options are ignored"],
	"-d" => [false, "Delete the named route instead of adding it"],
	"-D" => [false, "Delete all routes (does not require a subnet)"]
)

@@exec_opts.parse(args) { |opt, idx, val|
	v = val.to_s.strip
	case opt
	when "-h"
		usage
		raise Rex::Script::Completed
	when "-s"
		if v =~ /[0-9\x2e]+\x2f[0-9]{1,2}/
			subnet,cidr = v.split("\x2f")
			netmask = Rex::Socket.addr_ctoa(cidr.to_i)
		else
			subnet = v
		end
	when "-n"
		if (0..32) === v.to_i
			netmask = Rex::Socket.addr_ctoa(v.to_i)
		else
			netmask = v
		end
	when "-p"
		print_only = true
	when "-d"
		remove_route = true
	when "-D"
		remove_all_routes = true
	end
}

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
	raise Rex::Script::Completed
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
	raise Rex::Script::Completed
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

# Adds a route to the framework instance
def add_route(opts={})
	subnet = opts[:subnet]
	netmask = opts[:netmask] || "255.255.255.0" # Default class C
	Rex::Socket::SwitchBoard.add_route(subnet, netmask, session)
end

# Removes a route to the framework instance
def delete_route(opts={})
	subnet = opts[:subnet]
	netmask = opts[:netmask] || "255.255.255.0" # Default class C
	Rex::Socket::SwitchBoard.remove_route(subnet, netmask, session)
end


# Defines usage
def usage()
	print_status "Usage:   run autoroute [-r] -s subnet -n netmask"
	print_status "Examples:"
	print_status "  run autoroute -s 10.1.1.0 -n 255.255.255.0  # Add a route to 10.10.10.1/255.255.255.0"
	print_status "  run autoroute -s 10.10.10.1                 # Netmask defaults to 255.255.255.0"
	print_status "  run autoroute -s 10.10.10.1/24              # CIDR notation is also okay"
	print_status "  run autoroute -p                            # Print active routing table"
	print_status "  run autoroute -d -s 10.10.10.1              # Deletes the 10.10.10.1/255.255.255.0 route"
	print_status "Use the \"route\" and \"ipconfig\" Meterpreter commands to learn about available routes"
	print_error "Deprecation warning: This script has been replaced by the post/windows/manage/autoroute module"
end

# Validates the command options
def validate_cmd(subnet=nil,netmask=nil)
	if subnet.nil?
		print_error "Missing -s (subnet) option"
		return false
	end

	unless(check_ip(subnet))
		print_error "Subnet invalid (must be IPv4)"
		usage
		return false
	end

	if(netmask and !(Rex::Socket.addr_atoc(netmask)))
		print_error "Netmask invalid (must define contiguous IP addressing)"
		usage
		return false
	end

	if(netmask and !check_ip(netmask))
		print_error "Netmask invalid"
		return usage
	end
	true
end

if print_only
	print_routes()
	raise Rex::Script::Completed
end

if remove_all_routes
	delete_all_routes()
	raise Rex::Script::Completed
end

raise Rex::Script::Completed unless validate_cmd(subnet,netmask)

if remove_route
	print_status("Deleting route to %s/%s..." % [subnet,netmask])
	route_result = delete_route(:subnet => subnet, :netmask => netmask)
else
	print_status("Adding a route to %s/%s..." % [subnet,netmask])
	route_result = add_route(:subnet => subnet, :netmask => netmask)
end

if route_result
	print_good "%s route to %s/%s via %s" % [
		(remove_route ? "Deleted" : "Added"),
		subnet,netmask,client.sock.peerhost
	]
else
	print_error "Could not %s route" % [(remove_route ? "delete" : "add")]
end

if Rex::Socket::SwitchBoard.routes.size > 0
	print_status "Use the -p option to list all active routes"
end

