# -*- coding: binary -*-

##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Generate TCP/UDP Outbound Traffic On Multiple Ports',
                      'Description'   => %q(
                        This module is designed to generate TCP or UDP traffic across a sequence of ports.
                        It is essentially designed to help to find firewall holes and egress filtering.
                        All it does is generate traffic on the port range you specify; it is up to you to
                        run a listener/tcpdump or something on the endpoint to determine which packets
                        made it through. You could use https://github.com/stufus/egresscheck-framework to help
                        with acquiring and parsing packet captures.

                        It can be run in two modes; WINAPI mode and NATIVE mode.

                        In NATIVE mode, connections will be generated using Rex sockets, meaning that a route will
                        need to exist to ensure that meterpreter is generating the traffic. This module will add
                        and remove routes as needed in order to facilitate this.

                        In WINAPI mode (Windows only), this will use Windows APIs to generate the traffic.

                        Neither mode requires administrative privileges on the client side.
                       ),
                      'License'       => MSF_LICENSE,
                      'Author'        => 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
                      'Platform'      => [ 'win', 'linux' ],
                      'SessionTypes'  => ['meterpreter']
                     ))

    register_options(
      [
        OptAddress.new('TARGET', [ true, 'Destination IP address.']),
        OptString.new('PORTS', [true, 'Ports to test.', '22,23,53,80,88,443,445']),
        OptEnum.new('PROTOCOL', [ true, 'Protocol to use.', 'TCP', [ 'TCP', 'UDP' ]]),
        OptEnum.new('METHOD', [ true, 'The mechanism by which the packets are generated. Can be NATIVE (use normal sockets) or, for Windows usage, call Win32 APIs specifically using Railgun.', 'NATIVE', [ 'NATIVE', 'WINAPI' ]]),
        OptInt.new('THREADS', [true, 'Number of simultaneous threads/connections to try.', '20'])
      ], self.class)
  end

  def winapi_create_socket(proto)
    if proto == 'TCP'
      client.railgun.ws2_32.socket('AF_INET', 'SOCK_STREAM', 'IPPROTO_TCP')
    elsif proto == 'UDP'
      client.railgun.ws2_32.socket('AF_INET', 'SOCK_DGRAM', 'IPPROTO_UDP')
    end
  end

  def native_init_connect(proto, ip, port, num)
    vprint_status("[#{num}:NATIVE] Connecting to #{ip} port #{proto}/#{port}")
    if proto == 'TCP'
      begin
        Rex::Socket::Tcp.create(
          'PeerHost' => ip,
          'PeerPort' => port,
          'Timeout' => 1
        )
       rescue
         vprint_status("[#{num}:NATIVE] Error connecting to #{ip} #{proto}/#{port}")
      end
    elsif proto == 'UDP'
      begin
        rudp = Rex::Socket::Udp.create(
          'PeerHost' => ip,
          'PeerPort' => port,
          'Timeout' => 1
        )
        rudp.sendto('.', ip, port, 0) if rudp
       rescue
         vprint_status("[#{num}:NATIVE] Error connecting to #{ip} #{proto}/#{port}")
      end
    end
  end

  def winapi_make_connection(remote, dst_port, socket_handle, proto)
    sock_addr = "\x02\x00"
    sock_addr << [dst_port].pack('n')
    sock_addr << Rex::Socket.addr_aton(remote)
    sock_addr << "\x00" * 8
    if (proto == 'TCP')
      client.railgun.ws2_32.connect(socket_handle, sock_addr, 16)
    elsif (proto == 'UDP')
      client.railgun.ws2_32.sendto(socket_handle, ".", 0, 0, sock_addr, 16)
    end
  end

  def run
    type = datastore['METHOD']
    remote = datastore['TARGET']
    thread_num = datastore['THREADS']
    proto = datastore['PROTOCOL']

    # If we want WINAPI egress, make sure winsock is loaded
    if type == 'WINAPI'
      unless client.railgun.ws2_32
        print_error("This method requires railgun and support for winsock APIs. Try using the NATIVE method instead.")
        return
      end
    end

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    workload_ports = []
    workload_cycle = 0
    completed_cycle = false

    if thread_num > 1
      # Now we need to divvy up the ports into pots for each thread
      while !ports.nil? && !ports.empty?

        # If that group hasn't had its own ports array yet, give it some
        workload_ports[workload_cycle] = [] if workload_ports[workload_cycle].nil?

        # Add the port to the array to test
        workload_ports[workload_cycle] << ports.shift

        # Now increase the cycle until it goes above threads
        workload_cycle += 1
        if workload_cycle >= thread_num
          completed_cycle = true
          workload_cycle = 0
        end

      end

      if completed_cycle == false && thread_num > workload_cycle
        thread_num = workload_cycle
        vprint_status("Reduced threads to #{thread_num}.")
      else
        vprint_status("Number of threads: #{thread_num}.")
      end
    end

    return unless add_route_if_necessary(type, remote)

    print_status("Generating #{proto} traffic to #{remote}...")
    if thread_num > 1
      a = []
      0.upto(thread_num - 1) do |num|
        a << framework.threads.spawn("Module(#{refname})-#{remote}-#{proto}", false, workload_ports[num]) do |portlist|
          portlist.each do |dport|
            egress(type, proto, remote, dport, num)
          end
        end
      end
      a.map(&:join)
    else
      ports.each do |dport|
        egress(type, proto, remote, dport, num)
      end
    end

    remove_route_if_necessary(type, remote)

    print_status("#{proto} traffic generation to #{remote} completed.")
      end

  def add_route_if_necessary(type, remote)
    if type == 'NATIVE'
      unless (gw = framework.sessions.get(datastore['SESSION'])) && (gw.is_a?(Msf::Session::Comm))
        print_error("Error getting session to route egress traffic through to #{remote}")
        return FALSE
      end

      if Rex::Socket::SwitchBoard.add_route(remote, '255.255.255.255', gw)
        print_status("Adding route to direct egress traffic to #{remote}")
        return TRUE
      else
        print_error("Error adding route to direct egress traffic to #{remote}")
        return FALSE
      end
    end
  end

  def remove_route_if_necessary(type, remote)
    if type == 'NATIVE'
      route_result = Rex::Socket::SwitchBoard.remove_route(remote, '255.255.255.255', gw)
      if route_result
        print_status("Removed route needed to direct egress traffic to #{remote}")
      else
        print_error("Error removing route needed to direct egress traffic to #{remote}")
      end
    end
  end

  def egress(type, proto, remote, dport, num)
    if type == 'WINAPI'
      winapi_egress_to_port(proto, remote, dport, num)
    elsif type == 'NATIVE'
      native_init_connect(proto, remote, dport, num)
    end
  end

  # This will generate a packet on proto <proto> to IP <remote> on port <dport>
  def winapi_egress_to_port(proto, remote, dport, num)
    socket_handle = winapi_create_socket(proto)
    if socket_handle['return'] == 0
      vprint_status("[#{num}:WINAPI] Error setting up socket for #{remote}; Error: #{socket_handle['GetLastError']}")
      return
    else
      vprint_status("[#{num}:WINAPI] Set up socket for #{remote} port #{proto}/#{dport} (Handle: #{socket_handle['return']})")
   end

    vprint_status("[#{num}:WINAPI] Connecting to #{remote}:#{proto}/#{dport}")
    r = winapi_make_connection(remote, dport, socket_handle['return'], proto)
    if r['GetLastError'] == 0
      vprint_status("[#{num}:WINAPI] Connection packet sent successfully #{proto}/#{dport}")
    else
      vprint_status("[#{num}:WINAPI] There was an error sending a connect packet for #{proto} socket (port #{dport}) Error: #{r['GetLastError']}")
   end

    client.railgun.ws2_32.closesocket(socket_handle['return'])
  end
end
