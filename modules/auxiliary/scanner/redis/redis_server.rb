##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Redis
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Redis-server Scanner',
      'Description'  => %q{
          This module scans for Redis server. By default Redis has no auth. If auth
        (password only) is used, it is then possible to execute a brute force attack on
        the server. This scanner will find open or password protected Redis servers and
        report back the server information
      },
      'Author'       => [ 'iallison <ian[at]team-allison.com>', 'Nixawk' ],
      'License'      => MSF_LICENSE))

    register_options([Opt::RPORT(6379)])
  end

  def run_host(_ip)
    vprint_status("#{peer} -- contacting redis")
    begin
      connect
      data = redis_command('PING')
      report_service(host: rhost, port: rport, name: "redis server", info: data)
      print_good("#{peer} -- found redis")
    rescue Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout,
           Rex::ConnectionRefused, ::Timeout::Error, ::EOFError, ::Errno::ETIMEDOUT => e
      vprint_error("#{peer} -- error while communicating: #{e}")
    ensure
      disconnect
    end
  end
end
