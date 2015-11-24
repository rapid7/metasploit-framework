# -*- coding: binary -*-

##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Generate TCP/UDP Outbound Traffic On Multiple Ports',
                      'Description'   => %q(
                        This module is designed to generate TCP or UDP traffic across a sequence of ports.
                        It is essentially designed to help to find firewall holes and egress filtering.
                        All it does is generate traffic on the port range you specify; it is up to you to
                        run a listener/tcpdump or something on the endpoint to determine which packets
                        made it through.

                        It will not honour any metasploit/meterpreter specific routes for the very good reason
                        that the purpose is to judge connectivity from the box on its own, not to channel
                        this traffic through existing established connections.

                        It does not require administrative privileges and will use normal connection APIs.
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
    if (proto == 'TCP')
      client.railgun.ws2_32.socket('AF_INET', 'SOCK_STREAM', 'IPPROTO_TCP')
    elsif (proto == 'UDP')
      client.railgun.ws2_32.socket('AF_INET', 'SOCK_DGRAM', 'IPPROTO_UDP')
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
      client.railgun.ws2_32.sendto(socket_handle, "", 0, 0, sock_addr, 16)
    end
  end

  def winapi_egress
    unless session.railgun.ws2_32
      print_error("This module requires Windows/winsock APIs")
      return
    end

    remote = datastore['TARGET']
    thread_num = datastore['THREADS']
    proto = datastore['PROTOCOL']
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    workload_ports = []
    workload_cycle = 0
    completed_cycle = false

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
      print_status("Reduced threads to #{thread_num}.")
    else
      print_status("Number of threads: #{thread_num}.")
    end

    print_status("Generating #{proto} traffic to #{remote}...")

    a = []
    0.upto(thread_num - 1) do |num|
      a << framework.threads.spawn("Module(#{refname})", false, workload_ports[num]) do |portlist|
        portlist.each do |dport|
          socket_handle = winapi_create_socket(proto)
          if socket_handle['return'] == 0
            vprint_status("[#{num}] Error setting up socket for #{remote}; Error: #{socket_handle['GetLastError']}")
            break
          else
            vprint_status("[#{num}] Set up socket for #{remote} port #{proto}/#{dport} (Handle: #{socket_handle['return']})")
          end

          vprint_status("[#{num}] Connecting to #{remote}:#{proto}/#{dport}")
          r = winapi_make_connection(remote, dport, socket_handle['return'], proto)
          if r['GetLastError'] == 0
            vprint_status("[#{num}] Connection packet sent successfully #{proto}/#{dport}")
          else
            vprint_status("[#{num}] There was an error sending a connect packet for #{proto} socket (port #{dport}) Error: #{r['GetLastError']}")
          end
          client.railgun.ws2_32.closesocket(socket_handle['return'])
        end
      end
    end
    a.map(&:join)

    print_status("#{proto} traffic generation to #{remote} completed.")
    0

  def run
    # If it is being run in Win32 API (Railgun) mode, call the WinAPI version of this
    if datastore['METHOD']=='WINAPI'
        winapi_egress
    else
        native_egress
    end
  end

end
end
