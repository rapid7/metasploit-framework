# Overwatch plugin - Active Routing and Session Management
#
# Author: sn0wfa11 - jhale85446[at]gmail.com
#
# Session stepping functionality borrowed on HDM's Beholder plugin.

module Msf

class Plugin::Overwatch < Msf::Plugin

  # Worker Thread
  #
  # @return [void] A useful return value is not expected here

  class OverwatchWorker
    attr_accessor :framework, :config, :driver, :thread
    attr_accessor :state

    def initialize(framework, config, driver)
      #self.state     = { }
      self.state     = Array.new
      self.framework = framework
      self.config    = config
      self.driver    = driver
      self.thread    = framework.threads.spawn('OverwatchWorker', false) {
        begin
          self.start
        rescue ::Exception => e
          $stderr.puts "OverwatchWorker: #{e.class} #{e.message}\n#{e.backtrace * "\n"}"
        end

        # Mark this worker as dead
        self.thread = nil
      }
    end

    def stop
      return unless self.thread
      self.thread.kill rescue nil
      self.thread = nil
    end

    # Starts the overwatch worker and loops through the open sessions
    # based on the defined timeframe.
    #
    # @return [void] A useful return value is not expected here
    def start
      self.driver.print_status("Overwatch started. Use 'overwatch_start -h' for plugin information.")

      bool_options = [ :autoroute, :reroute_stale, :ipv6, :kill_stale, :kill_stale_dup ]
      bool_options.each do |o|
        self.config[o] = (self.config[o].to_s =~ /^[yt1]/i) ? true : false # Set option to true if (true, yes, or 1)
      end

      int_options = [ :freq, :route_timeout, :session_timeout, :session_dup_timeout ]
      int_options.each do |o|
        self.config[o] = self.config[o].to_i
      end

      loop do
        framework.sessions.keys.each do |sid|

          begin
            if self.state[sid].nil? || (self.state[sid].last_update + self.config[:freq] < Time.now.to_f)
              process(sid)
            end

          # Error handling - Yea, lots of stuff in here to keep errors from popping up in the console when sessions die or go stale. 
          # We also skip sessions below that have more than three errors because they slow down processing.
          rescue Rex::TimeoutError => te # Error when a session stops responding and the requests time out.
            #Do Nothing for this error

          rescue Rex::Post::Meterpreter::RequestError => re # Error when a session does not have access to routing information.
            self.state[sid].add_error

          rescue ::Exception => e
            elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
          end
        end
        sleep(0.5) # This sleep time seams to work the best to keep processes from stepping on each other.
      end
    end

    # Manages the top level of processing the sessions.
    # Sessions must be fully operational before the subprocesses can work.
    #
    # @sid [int class] Session ID of the current session being processed
    #
    # @return [void] A useful return value is not expected here
    def process(sid)
      return unless framework.sessions[sid].info #Make sure session is fully active before processing
      type = framework.sessions[sid].type
      type = framework.sessions[sid].session_type if framework.sessions[sid].respond_to?(:session_type)

      self.state[sid] = SessionState.new(sid, framework.sessions[sid].inspect, type) if self.state[sid].nil?
      self.state[sid].update
      process_routing(sid) unless self.state[sid].errored_out?
      process_sessions(sid)
    end

    ##################################################################################
    # Route Management Functions
    ##################################################################################

    # Perform the routing operations
    # Response_timeout is changed to the defined stale time to stay consistant
    # and not wait 300 seconds for timeout.
    #
    # @sid [int class] Session ID of of the session currently being processed.
    #
    # @return [int array] Array of session id's for stale sessions based on routing settings.
    def process_routing(sid)
      return unless self.config[:autoroute]
      
      if self.config[:reroute_stale]
        stale_sids = get_stale_route_sids
        return if stale_sids.include? sid # Skip this session if it has been tagged as routing stale
      end

      if framework.sessions[sid].respond_to?(:response_timeout)
        last_known_timeout = framework.sessions[sid].response_timeout
        framework.sessions[sid].response_timeout = self.config[:route_timeout] # Don't want to wait 300 secs for a time out!
      end

      add_routes(sid, stale_sids) unless self.state[sid].host_add?
      host_add_route(sid, stale_sids) if self.state[sid].host_add?

      if framework.sessions[sid].respond_to?(:response_timeout) && last_known_timeout 
        framework.sessions[sid].response_timeout = last_known_timeout # Set it back now that we are done trying to add routes.
      end
    end

    # Step through all of the current sessions and look at their age.
    # Return an array of sessions that are passed the defined timeout age (route_timeout).
    # Skips sessions that are not compatabile with this check.
    #
    # @return [int array] Array of session id's for stale sessions based on routing settings.
    def get_stale_route_sids
      stale_sids = []
      framework.sessions.keys.each do | sid |
        next unless stale_check_compatible?(sid)
        session_age = Time.now.to_i - framework.sessions[sid].last_checkin.to_i
        stale_sids << sid if session_age >= self.config[:route_timeout]
      end
      return stale_sids
    end

    # Search for valid subnets on the target and attempt
    # add a route to each.
    #
    # @sid [int class] Session ID of the current session
    # @stale_sids [int array] Array of session id's of sessions marked as stale
    #
    # @return [void] A useful return value is not expected here
    def add_routes(sid, stale_sids)
      return unless route_compatible?(sid)
      return unless framework.sessions[sid].alive?

      framework.sessions[sid].net.config.each_route do | route |  # This line is where errors are thrown for python, php, etc...
        if (Rex::Socket.is_ipv4?(route.subnet) && Rex::Socket.is_ipv4?(route.netmask))
          subnet = get_subnet_ipv4(route.subnet, route.netmask) # Make sure that the subnet is actually a subnet and not an IP address. Android phones like to send over their IP.
          next unless is_routable_ipv4?(subnet, route.netmask)

        # Optional IPv6 routing
        elsif (Rex::Socket.is_ipv6?(route.subnet) && Rex::Socket.is_ipv6?(route.netmask))
          next unless self.config[:ipv6]
          subnet = route.subnet
          next unless is_routeable_ipv6?(subnet, route.netmask)

        else
          next
        end

        if subnet
          remove_if_stale(subnet, route.netmask, sid, stale_sids) if self.config[:reroute_stale]

          if !Rex::Socket::SwitchBoard.route_exists?(subnet, route.netmask)
            begin
              Rex::Socket::SwitchBoard.add_route(subnet, route.netmask, framework.sessions[sid])
            rescue ::Exception => e
              elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
            end
          end
        end
      end
      add_interface_routes(sid, stale_sids) # Check interface list for more possible routes
    end

    # Look at network interfaces as options for additional routes.
    # If the routes are not already included they will be added.
    #
    # @sid [int class] session id of the current session
    # @stale_sids [int array] array of session id's of sessions marked as stale
    #
    # @return [true] A route from the interface list was added
    # @return [false] No additional routes were added
    def add_interface_routes(sid, stale_sids)
      return unless interface_compatible?(sid)
      return unless framework.sessions[sid].alive?

      framework.sessions[sid].net.config.each_interface do | interface | # Step through each of the network interfaces

        (0..(interface.addrs.size - 1)).each do | index | # Step through the addresses for the interface

          ip_addr = interface.addrs[index]
          netmask = interface.netmasks[index]

          next unless (Rex::Socket.is_ipv4?(ip_addr) && Rex::Socket.is_ipv4?(netmask)) # Pick out the IPv4 addresses
          subnet = get_subnet_ipv4(ip_addr, netmask)
          next unless is_routable_ipv4?(subnet, netmask)

          if subnet
            remove_if_stale(subnet, netmask, sid, stale_sids) if self.config[:reroute_stale]

            if !Rex::Socket::SwitchBoard.route_exists?(subnet, netmask)
              begin
                Rex::Socket::SwitchBoard.add_route(subnet, netmask, framework.sessions[sid])
              rescue ::Exception => e
                elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
              end
            end
          end 
        end
      end
    end

    # Uses the session_host information to add a standard class C network.
    # This is primarliy for python meterpreter sessions that do not have
    # access to the host's routing table, but return the correct value for
    # session_host
    #
    # @sid [int class] Session ID of the current session
    # @stale_sids [int array] Array of session id's of sessions marked as stale
    #
    # @return [void] A useful return value is not expected here
    def host_add_route(sid, stale_sids)
      return unless framework.sessions[sid].alive?
      return unless framework.sessions[sid].respond_to?(:net)

      ip_addr = framework.sessions[sid].session_host
      return unless Rex::Socket.is_ipv4?(ip_addr)

      netmask = "255.255.255.0"
      subnet = get_subnet_ipv4(ip_addr, netmask)
      return unless is_routable_ipv4?(subnet, netmask)

      if subnet
        remove_if_stale(subnet, netmask, sid, stale_sids) if self.config[:reroute_stale]

        if !Rex::Socket::SwitchBoard.route_exists?(subnet, netmask)
          begin
            Rex::Socket::SwitchBoard.add_route(subnet, netmask, framework.sessions[sid])
          rescue ::Exception => e
            elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
          end
        end
      end
    end

    # Removes routes associated with stale sessions only if they are
    # also present in sessions that are still active.
    #
    # @subnet [string class] route subnet
    # @netmask [string array] route netmask
    # @curr_sid [int class] Session ID of the current session being processed
    # @stale_sids [int array] Array of session ID's that have been marked as stale.
    #
    # @return [void] A useful return value is not expected here
    def remove_if_stale(subnet, netmask, curr_sid, stale_sids)
      Rex::Socket::SwitchBoard.each do | route |
        if stale_sids.include? route.comm.sid # See if a route is associated with a stale session
          if route.subnet == subnet && route.netmask == netmask # See if that route matches the one currently being processed
            begin
              Rex::Socket::SwitchBoard.remove_route(route.subnet, route.netmask, route.comm) # Remove so fresh matching route can be added
            rescue ::Exception => e
              elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
            end
            return
          end
        end
      end
    end

    # Take an IP address and a netmask and return the appropreate subnet "Network"
    #
    # @ip_addr [string class] Input IPv4 Address
    # @netmask [string class] Input IPv4 Netmask
    #
    # @return [string class] The subnet related to the IP address and netmask
    # @return [nil class] Something is out of range
    def get_subnet_ipv4(ip_addr, netmask)
      #return nil unless validate_cmd(ip_addr, netmask) #make sure IP and netmask are valid

      nets = ip_addr.split('.')
      masks = netmask.split('.')
      output = ""

      (0..3).each do | index |
        octet = get_subnet_ipv4_octet(int_or_nil(nets[index]), int_or_nil(masks[index]))
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
    def get_subnet_ipv4_octet(net, mask)
      return nil unless (net && mask)
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

    # This function will exclude loopback, multicast, and default routes
    #
    # @subnet [string class] IPv4 subnet or address to check
    # @netmask [string class] IPv4 netmask to check
    #
    # @return [true]  If good to add
    # @return [false] If not
    def is_routable_ipv4?(subnet, netmask)
      if subnet =~ /^224\.|^127\./
        return false
      elsif subnet == '0.0.0.0'
        return false
      elsif netmask == '255.255.255.255'
        return false
      end
      return true
    end

    # This function will exclude link-local, multicast, and default routes
    #
    # @subnet [string class] IPv6 subnet or address to check
    # @netmask [string class] IPv6 netmask to check
    #
    # @return [true]  If good to add
    # @return [false] If not
    def is_routeable_ipv6?(subnet, netmask)
      #return false unless validate_cmd(subnet, netmask)

      if netmask == 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        return false
      elsif subnet =~ /^fe80::/  # Link-Local Subnet
        return false
      elsif subnet =~ /^fe02::/  # Interior Multicast
        return false
      elsif subnet =~ /^fe01::/  # Exterior Multicast
        return false
      elsif subnet == '::'       # Default Route
        return false
      end
      return true
    end

    ###############################################################################
    # Session Management Functions
    ###############################################################################

    # Processing function for session management
    #
    # @sid [int class] Session ID of the current session
    #
    # @return [void] A useful return value is not expected here
    def process_sessions(sid)
      kill_stale(sid) if self.config[:kill_stale]
      kill_stale_dup(sid) if self.config[:kill_stale_dup]
    end

    # Kills a session that is marked as stale based on user settings
    #
    # @sid [int class] Session ID of the current session
    #
    # @return [void] A useful return value is not expected here
    def kill_stale(sid)
      return unless framework.sessions[sid].respond_to?(:last_checkin)
      session_age = Time.now.to_i - framework.sessions[sid].last_checkin.to_i
      if session_age >= self.config[:session_timeout]
        self.driver.print_status("Session #{sid.to_s} has become stale and is being killed.")
        begin
          framework.sessions[sid].kill
        rescue ::Exception => e
          elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
        end
        return
      end
    end

    # Kills a session that is marked as stale based on user settings
    # that has a duplicate or twin session that is still active
    #
    # @sid [int class] Session ID of the current session
    #
    # @return [void] A useful return value is not expected here
    def kill_stale_dup(sid)
      return unless kill_dup_compatible?(sid)
      session_age = Time.now.to_i - framework.sessions[sid].last_checkin.to_i
      if session_age >= self.config[:session_dup_timeout]

        framework.sessions.keys.each do | sid_other |
          next if sid == sid_other
          next unless kill_dup_compatible?(sid_other)
          session_age_other = Time.now.to_i - framework.sessions[sid_other].last_checkin.to_i
          if is_dup?(sid, sid_other) && session_age >= session_age_other
            self.driver.print_status("Session #{sid.to_s} is stale and is being killed. Duplicate as Session #{sid_other.to_s}")
            begin
              framework.sessions[sid].kill
            rescue ::Exception => e
              elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
            end
            return
          end
        end
      end
    end

    # Compares the two sessions to see if they match enough to kill the
    # stale session.
    #
    # @sid_1 [int class] Session 1 to compare
    # @sid_2 [int class] Session 2 to compare
    #
    # @return [bool class] True - Session has a twin, False - Session does not 
    def is_dup?(sid_1, sid_2)
      session1 = framework.sessions[sid_1]
      session2 = framework.sessions[sid_2]

      session1.info == session2.info &&
      session1.session_host == session2.session_host &&
      session1.type == session2.type &&
      session1.platform == session1.platform && 
      session1.machine_id == session2.machine_id
    end

    ###############################################################################
    # Compatibility Checks
    ###############################################################################

    # Checks to see if the session has routing capabilities
    #
    # @sid [int class] Session ID of the current session
    #
    # @return [true class] Session has routing capabilities
    # @return [false class] Session does not
    def route_compatible?(sid)
      framework.sessions[sid].respond_to?(:net) &&
      framework.sessions[sid].net.config.respond_to?(:each_route)
    end

    # Checks to see if the session has capabilities of accessing network interfaces
    #
    # @sid [int class] Session ID of the current session
    #
    # @return [true class] Session has ability to access network interfaces
    # @return [false class] Session does not
    def interface_compatible?(sid)
      framework.sessions[sid].respond_to?(:net) &&
      framework.sessions[sid].net.config.respond_to?(:each_interface)
    end

    # Checks to see if the session responds to the last_checkin request
    #
    # @sid [int class] Session ID of the current session
    #
    # @return [true class] Session responds to last_checkin
    # @return [false class] Session does not
    def stale_check_compatible?(sid)
      framework.sessions[sid].respond_to?(:last_checkin)
    end

    # Checks to see if the session is able to be checked for twins
    #
    # @sid [int class] Session ID of the current session
    #
    # @return [true class] Session can be checked for twins
    # @return [false class] Session can not
    def kill_dup_compatible?(sid)
      framework.sessions[sid].respond_to?(:last_checkin) &&
      framework.sessions[sid].respond_to?(:info) &&
      framework.sessions[sid].respond_to?(:session_host) &&
      framework.sessions[sid].respond_to?(:type) &&
      framework.sessions[sid].respond_to?(:platform) &&
      framework.sessions[sid].respond_to?(:machine_id)
    end
  end

  ###################################################################################
  # Command Dispatcher
  ###################################################################################

  class OverwatchCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    # Set Defaults
    @@overwatch_config = {
      autoroute: true,
      reroute_stale: true,
      route_timeout: 30,
      kill_stale: false,
      kill_stale_dup: false,
      session_timeout: 86400,
      session_dup_timeout: 14400,
      freq: 10, # Ten Seconds - Appears to be a good balance for this plugin
      ipv6: false,
    }

    @@overwatch_worker = nil

    def name
      "Overwatch"
    end

    def commands
      {
        'overwatch_start'         => "Start route and session management",
        'overwatch_stop'          => "Stop route and session management",
        'overwatch_config'        => "Configure plugin parameters",
        'overwatch_status'        => "Show current plugin status"
      }
    end

    def cmd_overwatch_stop(*args)
      unless @@overwatch_worker
        print_error("Error: Overwatch is not active")
        return
      end

      print_status("Overwatch is shutting down...")
      stop_overwatch
    end

    def cmd_overwatch_config(*args)
      parse_config(*args)
      cmd_overwatch_status
    end

    def cmd_overwatch_status
      print_line("")
      print_good("Overwatch is running.\n") if @@overwatch_worker
      print_error("Overwatch is stopped.\n") unless @@overwatch_worker
      
      print_status("Overwatch Configuration")
      print_status("----------------------")
      @@overwatch_config.each_pair do |k,v|
        print_status("  #{k}: #{v}")
      end
      print_status("----------------------\n")
    end

    def cmd_overwatch_start(*args)
      opts = Rex::Parser::Arguments.new(
        "-h"   => [ false,  "This help menu"],
      )

      opts.parse(args) do |opt, idx, val|
        case opt
        when "-h"
          print_line("\nOverwatch is a plugin for active routing and session management.")
          print_line("\nRoute Management:")
          print_line("'autoroute' will automatically add routes from active sessions' routing tables and network interfaces.")
          print_line("'reroute_stale' will automatically re-route to active sessions with matching routes if 'route_timeout' (in seconds) is reached by a non-responsive session.")
          print_line("'autoroute' must be active for 'reroute_stale' to function.")
          print_line("'ipv6' will add IPv6 routes from sessions in addition to IPv4 routes.")
          print_line("\nSession Management:")
          print_line("'kill_stale' will kill non-responsive sessions when they reach 'session_timeout' (in seconds).")
          print_line("'kill_stale_dup' will kill non-responsive sessions when they reach 'session_dup_timeout' (in seconds) only if the session has a twin based on domain, computer name, user ID, platform, computer ID, and IP address.")
          print_line("\nAdditional Options:")
          print_line("'freq' sets the cycle time in seconds.")
          print_line("\nUsage: overwatch_start [autoroute=<true|false>] [reroute_stale=<true|false>] [route_timeout=30] [ipv6=<true|false>]  [kill_stale=<true|false>] [kill_stale_dup=<true|false>] [session_timeout=86400] [session_dup_timeout=14400] [freq=10]")
          print_line("\nConfig Usage: overwatch_config [autoroute=<true|false>] [reroute_stale=<true|false>] [route_timeout=30] [ipv6=<true|false>] [kill_stale=<true|false>] [kill_stale_dup=<true|false>] [session_timeout=86400] [session_dup_timeout=14400] [freq=10]")
          print_line("\nUse 'overwatch_status' or 'overwatch_config' to view current settings.")
          print_line(opts.usage)
          
          return
        end
      end

      if @@overwatch_worker
        print_error("Error: Overwatch is already active, use overwatch_stop to terminate")
        return
      end

      parse_config(*args)
      start_overwatch
    end

    def parse_config(*args)
      new_config = args.map{|x| x.split("=", 2) }
      new_config.each do |c|
        unless @@overwatch_config.has_key?(c.first.to_sym)
          print_error("Invalid configuration option: #{c.first}")
          next
        end
        @@overwatch_config[c.first.to_sym] = c.last
      end
    end

    def stop_overwatch
      @@overwatch_worker.stop if @@overwatch_worker
      @@overwatch_worker = nil
    end

    def start_overwatch
      @@overwatch_worker = OverwatchWorker.new(framework, @@overwatch_config, driver)
    end

  end

  ####################################################################################
  # Plugin Interface
  ####################################################################################

  def initialize(framework, opts)
    super
    add_console_dispatcher(OverwatchCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('Overwatch')
  end

  def name
    "overwatch"
  end

  def desc
    "Active Route and Session Management"
  end

end #class Plugin::Overwatch < Msf::Plugin

class SessionState
  attr_accessor :error_count, :info, :last_update, :sid, :type, :host_add, :errored_out

  def initialize(sid, info, type)
    @sid = sid
    @info = info
    @type = type
    @error_count = 0
    @last_update = Time.now.to_f
    @host_add = type =~ /python/ ? true : false 
    @errored_out = type =~ /php/ ? true : false # PHP meterpreter sessions do not provide correct information for automatic routing.
  end

  def add_error
    @error_count = @error_count + 1
  end

  def update
    @last_update = Time.now.to_f
  end

  def errored_out?
     @error_count >= 3 ? true : false
  end

  def host_add?
    @host_add
  end

  def get_error_count
    @error_count
  end
end #class SessionState

end #module Msf

