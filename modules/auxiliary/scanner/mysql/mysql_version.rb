##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::MySQL

  def initialize
    super(
      'Name'        => 'MySQL Server Version Enumeration',
      'Description' => %q{
        Enumerates the version of MySQL servers.
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
      if session
        sql_conn = session.client
        version = sql_conn.server_info
        print_good("#{sql_conn.peerhost}:#{sql_conn.peerport} is running MySQL #{version}")
        report_service(
          :host => sql_conn.peerhost,
          :port => sql_conn.peerport,
          :name => "mysql",
          :info => version
        )
        return
      else
        socket = connect(false)
        data = socket.get_once(-1, 10)
        disconnect(socket)
      end

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
      print_good("#{rhost}:#{rport} is running MySQL #{version} (protocol #{proto})")
      report_service(
        :host => rhost,
        :port => rport,
        :name => "mysql",
        :info => version
      )
    end
  end
end
