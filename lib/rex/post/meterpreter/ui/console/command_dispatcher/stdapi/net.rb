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
  # Options for the resolve command
  #
  @@resolve_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.' ],
    '-f' => [true,  'Address family - IPv4 or IPv6 (default IPv4)'])

  #
  # Options for the route command.
  #
  @@route_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'])

  #
  # Options for the portfwd command.
  #
  @@portfwd_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-i' => [true,  'Index of the port forward entry to interact with (see the "list" command).'],
    '-l' => [true,  'Forward: local port to listen on. Reverse: local port to connect to.'],
    '-r' => [true,  'Forward: remote host to connect to.'],
    '-p' => [true,  'Forward: remote port to connect to. Reverse: remote port to listen on.'],
    '-R' => [false, 'Indicates a reverse port forward.'],
    '-L' => [true,  'Forward: local host to listen on (optional). Reverse: local host to connect to.'])

  #
  # Options for the netstat command.
  #
  @@netstat_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-S' => [true, 'Search string.'])

  #
  # Options for ARP command.
  #
  @@arp_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-S' => [true, 'Search string.'])

  #
  # List of supported commands.
  #
  def commands
    all = {
      'ipconfig' => 'Display interfaces',
      'ifconfig' => 'Display interfaces',
      'route'    => 'View and modify the routing table',
      'portfwd'  => 'Forward a local port to a remote service',
      'arp'      => 'Display the host ARP cache',
      'netstat'  => 'Display the network connections',
      'getproxy' => 'Display the current proxy configuration',
      'resolve'  => 'Resolve a set of host names on the target',
    }

    reqs = {
      'ipconfig' => ['stdapi_net_config_get_interfaces'],
      'ifconfig' => ['stdapi_net_config_get_interfaces'],
      'route'    => [
        # Also uses these, but we don't want to be unable to list them
        # just because we can't alter them.
        #'stdapi_net_config_add_route',
        #'stdapi_net_config_remove_route',
        'stdapi_net_config_get_routes'
      ],
      # Only creates tcp channels, which is something whose availability
      # we can't check directly at the moment.
      'portfwd'  => [],
      'arp'      => ['stdapi_net_config_get_arp_table'],
      'netstat'  => ['stdapi_net_config_get_netstat'],
      'getproxy' => ['stdapi_net_config_get_proxy'],
      'resolve'  => ['stdapi_net_resolve_host'],
    }

    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher.
  #
  def name
    'Stdapi: Networking'
  end

  #
  # Displays network connections of the remote machine.
  #
  def cmd_netstat(*args)
    if args.include?('-h')
      @@netstat_opts.usage
      return 0
    end

    connection_table = client.net.config.netstat
    search_term = nil

    @@netstat_opts.parse(args) { |opt, idx, val|
      case opt
      when '-S'
        search_term = val
        if search_term.nil?
          print_error("Enter a search term")
          return true
        else
          search_term = /#{search_term}/nmi
        end

      end
    }

    tbl = Rex::Text::Table.new(
    'Header'  => 'Connection list',
    'Indent'  => 4,
    'Columns' => [
      'Proto',
      'Local address',
      'Remote address',
      'State',
      'User',
      'Inode',
      'PID/Program name'
    ],
   'SearchTerm' => search_term)

    connection_table.each { |connection|
      tbl << [ connection.protocol, connection.local_addr_str, connection.remote_addr_str,
        connection.state, connection.uid, connection.inode, connection.pid_name]
    }

    if tbl.rows.length > 0
      print_line("\n#{tbl.to_s}")
    else
      print_line('Connection list is empty.')
    end
  end

  #
  # Displays ARP cache of the remote machine.
  #
  def cmd_arp(*args)
    if args.include?('-h')
      @@arp_opts.usage
      return 0
    end

    arp_table = client.net.config.arp_table
    search_term = nil

    @@arp_opts.parse(args) { |opt, idx, val|
      case opt
      when '-S'
        search_term = val
        if search_term.nil?
          print_error("Enter a search term")
          return true
        else
          search_term = /#{search_term}/nmi
        end
      end
    }

    tbl = Rex::Text::Table.new(
    'Header'  => 'ARP cache',
    'Indent'  => 4,
    'Columns' => [
      'IP address',
      'MAC address',
      'Interface'
    ],
    'SearchTerm' => search_term)

    arp_table.each { |arp|
      tbl << [ arp.ip_addr, arp.mac_addr, arp.interface ]
    }

    if tbl.rows.length > 0
      print_line("\n#{tbl.to_s}")
    else
      print_line('ARP cache is empty.')
    end
  end


  #
  # Displays interfaces on the remote machine.
  #
  def cmd_ipconfig(*args)
    ifaces = client.net.config.interfaces

    if (ifaces.length == 0)
      print_line('No interfaces were found.')
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
      args.unshift('list')
    end

    # Check to see if they specified -h
    @@route_opts.parse(args) do |opt, idx, val|
      case opt
      when '-h'
        cmd_route_help
        return true
      end
    end

    cmd = args.shift

    # Process the commands
    case cmd
      when 'list'
        routes = client.net.config.routes

        # IPv4
        tbl = Rex::Text::Table.new(
          'Header'  => 'IPv4 network routes',
          'Indent'  => 4,
          'Columns' => [
            'Subnet',
            'Netmask',
            'Gateway',
            'Metric',
            'Interface'
          ])

        routes.select {|route|
          Rex::Socket.is_ipv4?(route.netmask)
        }.each { |route|
          tbl << [ route.subnet, route.netmask, route.gateway, route.metric, route.interface ]
        }

        if tbl.rows.length > 0
          print_line("\n#{tbl.to_s}")
        else
          print_line('No IPv4 routes were found.')
        end

        # IPv6
        tbl = Rex::Text::Table.new(
          'Header'  => 'IPv6 network routes',
          'Indent'  => 4,
          'Columns' => [
            'Subnet',
            'Netmask',
            'Gateway',
            'Metric',
            'Interface'
          ])

        routes.select {|route|
          Rex::Socket.is_ipv6?(route.netmask)
        }.each { |route|
          tbl << [ route.subnet, route.netmask, route.gateway, route.metric, route.interface ]
        }

        if tbl.rows.length > 0
          print("\n#{tbl.to_s}")
        else
          print_line('No IPv6 routes were found.')
        end

      when 'add'
        # Satisfy check to see that formatting is correct
        unless Rex::Socket::RangeWalker.new(args[0]).length == 1
          print_error "Invalid IP Address"
          return false
        end

        unless Rex::Socket::RangeWalker.new(args[1]).length == 1
          print_error 'Invalid Subnet mask'
          return false
        end

        print_line("Creating route #{args[0]}/#{args[1]} -> #{args[2]}")

        client.net.config.add_route(*args)
      when 'delete'
        # Satisfy check to see that formatting is correct
        unless Rex::Socket::RangeWalker.new(args[0]).length == 1
          print_error 'Invalid IP Address'
          return false
        end

        unless Rex::Socket::RangeWalker.new(args[1]).length == 1
          print_error 'Invalid Subnet mask'
          return false
        end

        print_line("Deleting route #{args[0]}/#{args[1]} -> #{args[2]}")

        client.net.config.remove_route(*args)
      else
        print_error("Unsupported command: #{cmd}")
    end
  end

  def cmd_route_help
    print_line('Usage: route [-h] command [args]')
    print_line
    print_line('Display or modify the routing table on the remote machine.')
    print_line
    print_line('Supported commands:')
    print_line
    print_line('   add    [subnet] [netmask] [gateway]')
    print_line('   delete [subnet] [netmask] [gateway]')
    print_line('   list')
    print_line
    print_line
    print @@route_opts.usage
  end

  def cmd_route_tabs(str, words)
    return %w[add delete list] + @@route_opts.fmt.keys if words.length == 1
  end

  #
  # Starts and stops local port forwards to remote hosts on the target
  # network.  This provides an elementary pivoting interface.
  #
  def cmd_portfwd(*args)
    args.unshift('list') if args.empty?

    # For clarity's sake.
    lport = nil
    lhost = nil
    rport = nil
    rhost = nil
    reverse = false
    index = nil

    # Parse the options
    @@portfwd_opts.parse(args) { |opt, idx, val|
      case opt
        when '-h'
          cmd_portfwd_help
          return true
        when '-l'
          lport = val.to_i
        when '-L'
          lhost = val
        when '-p'
          rport = val.to_i
        when '-r'
          rhost = val
        when '-R'
          reverse = true
        when '-i'
          index = val.to_i
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
      when 'list'

        table = Rex::Text::Table.new(
          'Header'    => 'Active Port Forwards',
          'Indent'    => 3,
          'SortIndex' => -1,
          'Columns'   => ['Index', 'Local', 'Remote', 'Direction'])

        cnt = 0

        # Enumerate each TCP relay
        service.each_tcp_relay { |lhost, lport, rhost, rport, opts|
          next if (opts['MeterpreterRelay'] == nil)

          direction = 'Forward'
          direction = 'Reverse' if opts['Reverse'] == true

          if opts['Reverse'] == true
            table << [cnt + 1, "#{rhost}:#{rport}", "#{lhost}:#{lport}", 'Reverse']
          else
            table << [cnt + 1, "#{lhost}:#{lport}", "#{rhost}:#{rport}", 'Forward']
          end

          cnt += 1
        }

        print_line
        if cnt > 0
          print_line(table.to_s)
          print_line("#{cnt} total active port forwards.")
        else
          print_line('No port forwards are currently active.')
        end
        print_line

      when 'add'

        if reverse
          # Validate parameters
          unless lport && lhost && rport
            print_error('You must supply a local port, local host, and remote port.')
            return
          end

          begin
            channel = client.net.socket.create(
              Rex::Socket::Parameters.new(
                'LocalPort' => rport,
                'Proto'     => 'tcp',
                'Server'    => true
              )
            )

            # Start the local TCP reverse relay in association with this stream
            service.start_reverse_tcp_relay(channel,
              'LocalPort'         => rport,
              'PeerHost'          => lhost,
              'PeerPort'          => lport,
              'MeterpreterRelay'  => true)
          rescue Exception => e
            print_error("Failed to create relay: #{e.to_s}")
            return false
          end

        else
          # Validate parameters
          unless lport && rhost && rport
            print_error('You must supply a local port, remote host, and remote port.')
            return
          end

          # Start the local TCP relay in association with this stream
          service.start_tcp_relay(lport,
            'LocalHost'         => lhost,
            'PeerHost'          => rhost,
            'PeerPort'          => rport,
            'MeterpreterRelay'  => true,
            'OnLocalConnection' => Proc.new { |relay, lfd| create_tcp_channel(relay) })
        end

        print_status("Local TCP relay created: #{lhost}:#{lport} <-> #{rhost}:#{rport}")

      # Delete local port forwards
      when 'delete', 'remove', 'del', 'rm'

        found = false
        unless index.nil?
          counter = 1
          service.each_tcp_relay do |lh, lp, rh, rp, opts|
            if counter == index
              lhost, lport, rhost, rport = lh, lp, rh, rp
              reverse = opts['Reverse'] == true
              found = true
              break
            end

            counter += 1
          end

          unless found
            print_error("Invalid index: #{index}")
          end
        end

        if reverse
          # No remote port, no love.
          unless rport
            print_error('You must supply a remote port.')
            return
          end

          if service.stop_reverse_tcp_relay(lport)
            print_status("Successfully stopped reverse TCP relay on :#{lport}")
          else
            print_error("Failed to stop reverse TCP relay on #{lport}")
          end
        else
          # No local port, no love.
          unless lport
            print_error('You must supply a local port.')
            return
          end

          # Stop the service
          if service.stop_tcp_relay(lport, lhost)
            print_status("Successfully stopped TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
          else
            print_error("Failed to stop TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
          end
        end

      when 'flush'

        counter = 0
        service.each_tcp_relay do |lhost, lport, rhost, rport, opts|
          next if (opts['MeterpreterRelay'] == nil)

          if opts['Reverse'] == true
            if service.stop_reverse_tcp_relay(lport)
              print_status("Successfully stopped reverse TCP relay on :#{lport}")
            else
              print_error("Failed to stop reverse TCP relay on #{lport}")
              next
            end
          else
            if service.stop_tcp_relay(lport, lhost)
              print_status("Successfully stopped TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
            else
              print_error("Failed to stop TCP relay on #{lhost || '0.0.0.0'}:#{lport}")
              next
            end
          end

          counter += 1
        end
        print_status("Successfully flushed #{counter} rules")

      else
        cmd_portfwd_help
    end
  end

  def cmd_portfwd_help
    print_line 'Usage: portfwd [-h] [add | delete | list | flush] [args]'
    print_line
    print @@portfwd_opts.usage
  end

  def cmd_portfwd_tabs(str, words)
    return %w[add delete list flush] + @@portfwd_opts.fmt.keys if words.length == 1

    case words[-1]
    when '-L'
      return tab_complete_source_address
    when '-i'
      if client.respond_to?('pfservice')
        return (1..client.pfservice.each_tcp_relay { |lh, lp, rh, rp, opts| }.length).to_a.map!(&:to_s)
      end
    when 'add', 'delete', 'list', 'flush'
      return @@portfwd_opts.fmt.keys
    end

    []
  end

  def cmd_getproxy
    p = client.net.config.get_proxy_config
    print_line( "Auto-detect     : #{p[:autodetect] ? "Yes" : "No"}" )
    print_line( "Auto config URL : #{p[:autoconfigurl]}" )
    print_line( "Proxy URL       : #{p[:proxy]}" )
    print_line( "Proxy Bypass    : #{p[:proxybypass]}" )
  end

  #
  # Resolve 1 or more hostnames on the target session
  #
  def cmd_resolve(*args)
    args.unshift('-h') if args.length == 0

    hostnames = []
    family = AF_INET

    @@resolve_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_line('Usage: resolve host1 host2 .. hostN [-h] [-f IPv4|IPv6]')
        print_line
        print_line(@@resolve_opts.usage)
        return false
      when '-f'
        if val.downcase == 'ipv6'
          family = AF_INET6
        elsif val.downcase != 'ipv4'
          print_error("Invalid family: #{val}")
          return false
        end
      else
        hostnames << val
      end
    }

    response = client.net.resolve.resolve_hosts(hostnames, family)

    table = Rex::Text::Table.new(
      'Header'    => 'Host resolutions',
      'Indent'    => 4,
      'SortIndex' => 0,
      'Columns'   => ['Hostname', 'IP Address']
    )

    response.each do |result|
      if result[:ip].nil?
        table << [result[:hostname], '[Failed To Resolve]']
      else
        table << [result[:hostname], result[:ip]]
      end
    end

    print_line
    print_line(table.to_s)
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

