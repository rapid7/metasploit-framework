##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Jenkins Server Broadcast Enumeration',
        'Description'    => %q(
            This module sends out a udp broadcast packet querying for
            any Jenkins servers on the local network.
            Be advised that while this module does not identify the
            port on which Jenkins is running, the default port for
            Jenkins is 8080.
        ),
        'Author'         =>
          [
            'Adam Compton <adam_compton@rapid7.com>',
            'Matt Schmidt <matt_schmidt@rapid7.com>'
          ],
        'References'     =>
          [
            [ 'URL', 'https://wiki.jenkins-ci.org/display/JENKINS/Auto-discovering+Jenkins+on+the+network' ]
          ],
        'License'        => MSF_LICENSE
      )
    )
    deregister_options('RHOST', 'RPORT')
  end

  def parse_reply(pkt)
    # if empty packet, exit
    return if !pkt[1]

    # strip to just the IPv4 address
    if pkt[1] =~ /^::ffff:/
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end

    # check for and extract the version string
    ver = nil
    if !ver && pkt[0] =~ /version>(.*)<\/version/i
      ver = $1
    end

    # if a version was identified, then out and store to DB
    if ver
      print_status("Found Jenkins Server at: #{pkt[1]} version : #{ver}")
      report_host(
          host: pkt[1],
          info: "Jenkins v.#{ver} (port typically 8080)"
      )
    end
  end

  def run
    print_status('Sending Jenkins UDP Broadcast Probe ...')

    # create a udp socket
    self.udp_sock = Rex::Socket::Udp.create(
       'Context' => { 'Msf' => framework, 'MsfExploit' => self }
    )
    add_socket(self.udp_sock)

    # send a dummy packet to broadcast on port 33848
    udp_sock.sendto('\n', '255.255.255.255', 33848, 0)

    # loop a few times to account for slow responders
    iter = 0
    while (r = udp_sock.recvfrom(65535, 0.1)) && (iter < 10)
      parse_reply(r)
      iter += 1
    end
  end
end
