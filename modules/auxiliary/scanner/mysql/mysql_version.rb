##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'MySQL Server Version Enumeration',
      'Description' => %q{
        Enumerates the version of MySQL servers
      },
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(3306)
    ])
  end

  # Based on my mysql-info NSE script
  def run_host(ip)
    begin
      s = connect(false)
      data = s.get_once(-1,10)
      disconnect(s)
      if data.nil?
        print_error "The connection to #{rhost}:#{rport} timed out"
        return
      end
    rescue ::Rex::ConnectionError, ::EOFError
      vprint_error("#{rhost}:#{rport} - Connection failed")
      return
    rescue ::Exception
      print_error("Error: #{$!}")
      return
    end

    offset = 0

    l0, l1, l2 = data[offset, 3].unpack('CCC')
    length = l0 | (l1 << 8) | (l2 << 16)

    # Read a bad amount of data
    return if length != (data.length - 4)

    offset += 4

    proto = data[offset, 1].unpack('C')[0]

    # Application-level error condition
    if proto == 255
      offset += 2
      err_msg = Rex::Text.to_hex_ascii(data[offset..-1].to_s)
      print_status("#{rhost}:#{rport} is running MySQL, but responds with an error: #{err_msg}")
      report_service(
        :host => rhost,
        :port => rport,
        :name => "mysql",
        :info => "Error: #{err_msg}"
      )
    else
      offset += 1
      version = data[offset..-1].unpack('Z*')[0]
      print_status("#{rhost}:#{rport} is running MySQL #{version} (protocol #{proto})")
      report_service(
        :host => rhost,
        :port => rport,
        :name => "mysql",
        :info => version
      )
    end
  end
end
