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
        OptInt.new('TIMEOUT', [true, 'Timeout for the ICMP socket.', 500]),
      ], self.class)
  end

  def tcp_setup
    handler = client.railgun.ws2_32.socket('AF_INET', 'SOCK_STREAM', 'IPPROTO_TCP')
    if handler['GetLastError'] == 0
      vprint_status('TCP socket created successfully')
      return handler
    else
      print_error("There was an error setting the TCP socket; GetLastError: #{handler['GetLastError']}")
      return nil
    end
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
    h_tcp = tcp_setup

    remote = datastore['TARGET']
    to = datastore['TIMEOUT']

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    ports.each do |dport|
      print_status("Connecting to #{remote}:#{dport}")
      r = connections(remote, dport, h_tcp['return'])
      if r['GetLastError'] == 0
        print_status('TCP socket created successfully')
      else
        print_error("There was an error setting the TCP socket; GetLastError: #{r['GetLastError']}")
      end
    end
    client.railgun.ws2_32.closesocket(h_tcp['return'])
    return 0
  end

end
