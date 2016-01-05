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

    register_options([Opt::RPORT(6379)], self.class)

    deregister_options('RHOST')
  end

  def run_host(_ip)
    print_status("Scanning IP: #{peer}")
    begin
      connect
      data = redis_command('PING')
      report_service(:host => rhost,
                     :port => rport,
                     :name => "redis server",
                     :info => data)
    rescue ::Exception => e
      print_error("Unable to connect: #{e}")
      disconnect
    end
  end
end
