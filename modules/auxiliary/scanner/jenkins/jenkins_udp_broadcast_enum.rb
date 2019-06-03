##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
    deregister_udp_options
  end

  def parse_reply(pkt)
    # if empty packet, exit
    return unless pkt[1]

    # strip to just the IPv4 address
    if pkt[1] =~ /^::ffff:/
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end

    # check for and extract the version string
    ver = pkt[0].scan(/version>(.*)<\/version/i).flatten.first

    # if a version was identified, then out and store to DB
    if ver
      print_good("#{pkt[1]} - Found Jenkins Server #{ver} Version")
      report_host(
        host: pkt[1],
        info: "Jenkins v.#{ver} (port typically 8080)"
      )
    end
  end

  def run
    print_status('Sending Jenkins UDP Broadcast Probe ...')

    udp_sock = connect_udp

    udp_sock.sendto('\n', '255.255.255.255', 33848, 0)

    # loop a few times to account for multiple or slow responders
    iter = 0
    while (r = udp_sock.recvfrom(65535, 0.1)) && (iter < 20)
      parse_reply(r)
      iter += 1
    end
  end
end
