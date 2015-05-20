# -*- coding: binary -*-

##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Generate Outbound Traffic On Port Sequence',
      'Description'   => %q{
        This module is designed to generate TCP or UDP traffic across a sequence of ports.
        It is essentially designed to help to find firewall holes and egress filtering.
        All it does is generate traffic on the port range you specify; it is up to you to
        run a listener or wireshark or something on the endpoint to determine which packets
        made it through.
      },
      'License'       => MSF_LICENSE,
      'Author'        => 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
      'Platform'      => 'win',
      'SessionTypes'  => ['meterpreter'],
    ))

    register_options(
      [
        OptAddress.new('TARGET' , [ true, 'Destination IP address.']),
        OptString.new('PORTS', [true, 'Ports to test (e.g. 80,443,100-110).','80,443']),
        OptEnum.new('PROTOCOL', [ true, 'Protocol to use', 'TCP', [ 'TCP' ]]),
        OptInt.new('THREADS' , [true, 'Number of simultaneous threads/connections to try.','20']),
      ], self.class)
  end

  def tcp_setup
    client.railgun.ws2_32.socket('AF_INET', 'SOCK_STREAM', 'IPPROTO_TCP')
  end

  def connections(remote, dst_port, h_tcp)
    sock_addr = "\x02\x00"
    sock_addr << [dst_port].pack('n')
    sock_addr << Rex::Socket.addr_aton(remote)
    sock_addr << "\x00" * 8
    r = client.railgun.ws2_32.connect(h_tcp, sock_addr, 16)
  end

  def run
    session.railgun.ws2_32

    remote = datastore['TARGET']
    thread_num = datastore['THREADS']
    proto = datastore['PROTOCOL']
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    workload_ports = []
    workload_cycle = 0
    completed_cycle = false

    # Now we need to divvy up the ports into pots for each thread
    while(not ports.nil? and not ports.empty?) do 

        # If that group hasn't had its own ports array yet, give it some
        workload_ports[workload_cycle] = [] if workload_ports[workload_cycle].nil? 

        # Add the port to the array to test
        workload_ports[workload_cycle] << ports.shift

        # Now increase the cycle until it goes above threads
        workload_cycle = workload_cycle + 1
        if workload_cycle >= thread_num 
            completed_cycle = true
            workload_cycle = 0
        end

    end

    if completed_cycle == false and thread_num > workload_cycle
        thread_num = workload_cycle
        print_status("Reduced threads to #{thread_num} because there is not enough work for the remaining threads.")
    else
        print_status("Number of threads: #{thread_num}")
    end

    print_status("Generating #{proto} traffic to #{remote}...")
 
    a = []
    0.upto(thread_num-1) do |num|
          a << framework.threads.spawn("Module(#{self.refname})", false, workload_ports[num]) do |portlist|
            h_tcp = tcp_setup
            if h_tcp['return'] == 0
                print_error("[#{num}] Error setting up socket for #{remote}; Error: #{h_tcp['GetLastError']}")
                break
            else
                print_status("[#{num}] Set up socket for #{remote} to cover #{portlist.count} #{proto} port(s) (Handle: #{h_tcp['return']})")
            end

            portlist.each do |dport|
            vprint_status("[#{num}] Connecting to #{remote}:#{proto}/#{dport}")
            r = connections(remote, dport, h_tcp['return'])
            if r['GetLastError'] == 0
                vprint_status("[#{num}] Connection made successfully #{proto}/#{dport}")
            else
                vprint_status("[#{num}] There was an error setting the #{proto} socket (port #{dport}) Error: #{r['GetLastError']}")
            end
            end
            client.railgun.ws2_32.closesocket(h_tcp['return'])
          end
  end
  a.map { |x| x.join }

  print_status("#{proto} traffic generation to #{remote} completed.")
  return 0

end
end
