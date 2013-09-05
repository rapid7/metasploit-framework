##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  # Order is important here
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Ftp

  def initialize
    super(
      'Name'        => 'FTP Bounce Port Scanner',
      'Description' => %q{
        Enumerate TCP services via the FTP bounce PORT/LIST
        method, which can still come in handy every once in
        a while (I know of a server that still allows this
        just fine...).
      },
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
      OptAddress.new('BOUNCEHOST', [true, "FTP relay host"]),
      OptPort.new('BOUNCEPORT', [true, "FTP relay port", 21])
    ])

    deregister_options('RHOST', 'RPORT')
  end

  # No IPv6 support yet
  def support_ipv6?
    false
  end

  def run_host(ip)
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    if ports.empty?
      print_error("Error: No valid ports specified")
      return
    end

    datastore['RHOST'] = datastore['BOUNCEHOST']
    datastore['RPORT'] = datastore['BOUNCEPORT']

    return if not connect_login

    ports.each do |port|
      # Clear out the receive buffer since we're heavily dependent
      # on the response codes.  We need to do this between every
      # port scan attempt unfortunately.
      while true
        r = self.sock.get(0.25)
        break if not r or r.empty?
      end

      begin
        host = (ip.split('.') + [port / 256, port % 256]).join(',')

        resp = send_cmd(["PORT", host])

        if resp =~ /^5/
          #print_error("Got error from PORT to #{ip}:#{port}")
          next
        elsif not resp
          next
        end

        resp = send_cmd(["LIST"])

        if resp =~ /^[12]/
          print_status(" TCP OPEN #{ip}:#{port}")
          report_service(:host => ip, :port => port)
        end
      rescue ::Exception
        print_error("Unknown error: #{$!}")
      end
    end
  end
end
