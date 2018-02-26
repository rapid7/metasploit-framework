##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi Manage Network Route via Meterpreter Session',
        'Description'   => %q{This module manages session routing via an existing
          Meterpreter session. It enables other modules to 'pivot' through a
          compromised host when connecting to the named NETWORK and SUBMASK.
          Autoadd will search a session for valid subnets from the routing table
          and interface list then add routes to them. Default will add a default
          route so that all TCP/IP traffic not specified in the MSF routing table
          will be routed through the session when pivoting. See documentation for more
          'info -d' and click 'Knowledge Base'},
        'License'       => MSF_LICENSE,
        'Author'        =>
           [
             'todb',
             'Josh Hale "sn0wfa11" <jhale85446[at]gmail.com>'
           ],
        'SessionTypes'  => [ 'meterpreter']
      ))

    register_options(
      [
        OptString.new('SUBNET', [false, 'Subnet (IPv4, for example, 10.10.10.0)', nil]),
        OptString.new('NETMASK', [false, 'Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"', '255.255.255.0']),
        OptEnum.new('CMD', [true, 'Specify the autoroute command', 'autoadd', ['add','autoadd','print','delete','default']])
      ])
  end

  # Get the CMD string vs ACTION
  #
  # Backwards compatability: This was changed because the option name of "ACTION"
  # is special for some things, and indicates the :action attribute, not a datastore option.
  # However, this is a semi-popular module, though, so I'd prefer not to break people's
  # RC scripts that set ACTION. Note that ACTION is preferred over CMD.
  #
  # TODO: The better solution is to use 'Action' and 'DefaultAction' info elements,
  # but there are some squirelly problems right now with rendering these for post modules.
  #
  # @return [string class] cmd string
  def route_cmd
    if datastore['ACTION'].to_s.empty?
      datastore['CMD'].to_s.downcase.to_sym
    else
      wlog("Warning, deprecated use of 'ACTION' datastore option for #{self.fullname}'. Use 'CMD' instead.")
      datastore['ACTION'].to_s.downcase.to_sym
    end
  end

  # Run Method for when run command is issued
  #
  # @return [void] A useful return value is not expected here
  def run
    return unless session_good?

    print_status("Running module against #{sysinfo['Computer']}")

    case route_cmd()
    when :print
      print_routes()
    when :add
      if validate_cmd(datastore['SUBNET'],netmask)
        print_status("Adding a route to %s/%s..." % [datastore['SUBNET'],netmask])
        add_route(datastore['SUBNET'], netmask)
      end
    when :autoadd
      autoadd_routes
    when :default
      add_default
    when :delete
      if datastore['SUBNET']
        print_status("Deleting route to %s/%s..." % [datastore['SUBNET'],netmask])
        delete_route(datastore['SUBNET'], netmask)
      else
        delete_all_routes()
      end
    end
  end

  # Delete all routes from framework routing table.
  #
  # @return [void] A useful return value is not expected here
  def delete_all_routes
    if Rex::Socket::SwitchBoard.routes.size > 0
      print_status("Deleting all routes associated with session: #{session.sid.to_s}.")
      while true
        count = 0
        Rex::Socket::SwitchBoard.each do |route|
          if route.comm == session
            print_status("Deleting: #{route.subnet}/#{route.netmask}")
            delete_route(route.subnet, route.netmask)
          end
        end
        Rex::Socket::SwitchBoard.each do |route|
          count = count + 1 if route.comm == session
        end
        break if count == 0
      end
      print_status("Deleted all routes")
    else
      print_status("No routes associated with this session to delete.")
    end
  end

  # Print all of the active routes defined on the framework
  #
  # Identical functionality to command_dispatcher/core.rb, and
  # nearly identical code
  #
  # @return [void] A useful return value is not expected here
  def print_routes
    # IPv4 Table
    tbl_ipv4 = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header'  => "IPv4 Active Routing Table",
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

    # IPv6 Table
    tbl_ipv6 = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header'  => "IPv6 Active Routing Table",
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

    # Populate Route Tables
    Rex::Socket::SwitchBoard.each { |route|
      if (route.comm.kind_of?(Msf::Session))
        gw = "Session #{route.comm.sid}"
      else
        gw = route.comm.name.split(/::/)[-1]
      end

      tbl_ipv4 << [ route.subnet, route.netmask, gw ] if Rex::Socket.is_ipv4?(route.netmask)
      tbl_ipv6 << [ route.subnet, route.netmask, gw ] if Rex::Socket.is_ipv6?(route.netmask)
    }

    # Print Route Tables
    print(tbl_ipv4.to_s) if tbl_ipv4.rows.length > 0
    print(tbl_ipv6.to_s) if tbl_ipv6.rows.length > 0
    if (tbl_ipv4.rows.length + tbl_ipv6.rows.length) < 1
      print_status("There are currently no routes defined.")
    elsif (tbl_ipv4.rows.length < 1) && (tbl_ipv6.rows.length > 0)
      print_status("There are currently no IPv4 routes defined.")
    elsif (tbl_ipv4.rows.length > 0) && (tbl_ipv6.rows.length < 1)
      print_status("There are currently no IPv6 routes defined.")
    end
  end

  # Validation check on an IPv4 address
  #
  # Yet another IP validator. I'm sure there's some Rex
  # function that can just do this.
  #
  # @return [string class] IPv4 subnet
  def check_ip(ip=nil)
    return false if(ip.nil? || ip.strip.empty?)
    begin
      rw = Rex::Socket::RangeWalker.new(ip.strip)
      (rw.valid? && rw.length == 1) ? true : false
    rescue
      false
    end
  end

  # Converts a CIDR value to a netmask
  #
  # @return [string class] IPv4 netmask
  def cidr_to_netmask(cidr)
    int = cidr.gsub(/\x2f/,"").to_i
    Rex::Socket.addr_ctoa(int)
  end

  # Validates the user input 'NETMASK'
  #
  # @return [string class] IPv4 netmask
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

  # This function adds a route to the framework routing table
  #
  # @subnet [string class] subnet to add
  # @netmask [string class] netmask
  # @origin [string class] where route is coming from. Nill for none.
  #
  # @return [true]  If added
  # @return [false] If not
  def add_route(subnet, netmask, origin=nil)
  if origin
    origin = " from #{origin}"
  else
    origin = ""
  end

    begin
      if Rex::Socket::SwitchBoard.add_route(subnet, netmask, session)
        print_good("Route added to subnet #{subnet}/#{netmask}#{origin}.")
        return true
      else
        print_error("Could not add route to subnet #{subnet}/#{netmask}#{origin}.")
        return false
      end
    rescue ::Rex::Post::Meterpreter::RequestError => re
      print_error("Could not add route to subnet #{subnet}/#{netmask}#{origin}.")
      print_error("#{re.class} #{re.message}\n#{re.backtrace * "\n"}")
      return false
    end
  end

  # This function removes a route to the framework routing table
  #
  # @subnet [string class] subnet to add
  # @netmask [string class] netmask
  # @origin [string class] where route is coming from.
  #
  # @return [true]  If removed
  # @return [false] If not
  def delete_route(subnet, netmask)
    begin
      Rex::Socket::SwitchBoard.remove_route(subnet, netmask, session)
    rescue ::Rex::Post::Meterpreter::RequestError => re
      print_error("Could not remove route to subnet #{subnet}/#{netmask}")
      print_error("#{re.class} #{re.message}\n#{re.backtrace * "\n"}")
      return false
    end
  end

  # This function will exclude loopback, multicast, and default routes
  #
  # @subnet [string class] IPv4 subnet or address to check
  # @netmask [string class] IPv4 netmask to check
  #
  # @return [true]  If good to add
  # @return [false] If not
  def is_routable?(subnet, netmask)
    if subnet =~ /^224\.|^127\./
      return false
    elsif subnet == '0.0.0.0'
      return false
    elsif netmask == '255.255.255.255'
      return false
    end

    return true
  end

  # Search for valid subnets on the target and attempt
  # add a route to each. (Operation from auto_add_route plugin.)
  #
  # @return [void] A useful return value is not expected here
  def autoadd_routes
    return unless route_compatible?
    print_status("Searching for subnets to autoroute.")
    found = false

    begin
      session.net.config.each_route do | route |
        next unless (Rex::Socket.is_ipv4?(route.subnet) && Rex::Socket.is_ipv4?(route.netmask)) # Pick out the IPv4 addresses
        subnet = get_subnet(route.subnet, route.netmask) # Make sure that the subnet is actually a subnet and not an IP address. Android phones like to send over their IP.
        next unless is_routable?(subnet, route.netmask)

        if !Rex::Socket::SwitchBoard.route_exists?(subnet, route.netmask)
          found = true if add_route(subnet, route.netmask, "host's routing table")
        end
      end

    rescue ::Rex::Post::Meterpreter::RequestError => re
      print_status("Unable to get routes from session, trying interface list.")
    end

    if !autoadd_interface_routes && !found  # Check interface list for more possible routes
      print_status("Did not find any new subnets to add.")
    end
  end

  # Look at network interfaces as options for additional routes.
  # If the routes are not already included they will be added.
  #
  # @return [true] A route from the interface list was added
  # @return [false] No additional routes were added
  def autoadd_interface_routes
    return unless interface_compatible?
    found = false

    begin
      session.net.config.each_interface do | interface | # Step through each of the network interfaces

        (0..(interface.addrs.size - 1)).each do | index | # Step through the addresses for the interface

          ip_addr = interface.addrs[index]
          netmask = interface.netmasks[index]

          next unless (Rex::Socket.is_ipv4?(ip_addr) && Rex::Socket.is_ipv4?(netmask)) # Pick out the IPv4 addresses
          next unless is_routable?(ip_addr, netmask)

          subnet = get_subnet(ip_addr, netmask)

          if subnet
            if !Rex::Socket::SwitchBoard.route_exists?(subnet, netmask)
              found = true if add_route(subnet, netmask, interface.mac_name)
            end
          end

        end
      end
    rescue ::Rex::Post::Meterpreter::RequestError => error
      print_error("Unable to get interface information from session.")
    end
    return found
  end

  # Take an IP address and a netmask and return the appropreate subnet "Network"
  #
  # @ip_addr [string class] Input IPv4 Address
  # @netmask [string class] Input IPv4 Netmask
  #
  # @return [string class] The subnet related to the IP address and netmask
  # @return [nil class] Something is out of range
  def get_subnet(ip_addr, netmask)
    return nil if !validate_cmd(ip_addr, netmask) #make sure IP and netmask are valid

    nets = ip_addr.split('.')
    masks = netmask.split('.')
    output = ""

    (0..3).each do | index |
      octet = get_subnet_octet(int_or_nil(nets[index]), int_or_nil(masks[index]))
      return nil if !octet
      output << octet.to_s
      output << '.' if index < 3
    end
    return output
  end

  # Input an octet of an IPv4 address and the cooresponding octet of the
  # IPv4 netmask then return the appropreate subnet octet.
  #
  # @net  [integer class] IPv4 address octet
  # @mask [integer class] Ipv4 netmask octet
  #
  # @return [integer class] Octet of the subnet
  # @return [nil class] If an input is nil
  def get_subnet_octet(net, mask)
    return nil if !net || !mask

    subnet_range = 256 - mask  # This is the address space of the subnet octet

    multi = net / subnet_range # Integer division to get the multiplier needed to determine subnet octet

    return(subnet_range * multi) # Multiply to get subnet octet
  end

  # Take a string of numbers and converts it to an integer.
  #
  # @string [string class] Input string, needs to be all numbers (0..9)
  #
  # @return [integer class] Integer representation of the number string
  # @return [nil class] string contains non-numbers, cannot convert
  def int_or_nil(string)
    num = string.to_i
    num if num.to_s == string
  end

  # Add a default route to the routing table
  #
  # @return [void] A useful return value is not expected here
  def add_default
    subnet = '0.0.0.0'
    mask = '0.0.0.0'

    switch_board = Rex::Socket::SwitchBoard.instance
    print_status("Attempting to add a default route.")

    if !switch_board.route_exists?(subnet, mask)
      add_route(subnet, mask)
    end
  end

  # Checks to see if the session is ready.
  #
  # Some Meterpreter types, like python, can take a few seconds to
  # become fully established. This gracefully exits if the session
  # is not ready yet.
  #
  # @return [true class] Session is good
  # @return [false class] Session is not
  def session_good?
    if !session.info
      print_error("Session is not yet fully established. Try again in a bit.")
      return false
    end
    return true
  end

  # Checks to see if the session has routing capabilities
  #
  # @return [true class] Session has routing capabilities
  # @return [false class] Session does not
  def route_compatible?
    session.respond_to?(:net) &&
    session.net.config.respond_to?(:each_route)
  end

  # Checks to see if the session has capabilities of accessing network interfaces
  #
  # @return [true class] Session has ability to access network interfaces
  # @return [false class] Session does not
  def interface_compatible?
    session.respond_to?(:net) &&
    session.net.config.respond_to?(:each_interface)
  end

  # Validates the command options
  #
  # @return [true class] Everything is good
  # @return [false class] Not so much
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
    return true
  end
end
