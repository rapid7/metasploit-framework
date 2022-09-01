##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Redis
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Redis Command Execute Scanner',
      'Description'  => %q(
        This module locates Redis endpoints by attempting to run a specified
        Redis command.
      ),
      'Author'       => [ 'iallison <ian[at]team-allison.com>', 'Nixawk' ],
      'License'      => MSF_LICENSE))

    register_options(
      [
        Opt::RPORT(6379),
        OptString.new('COMMAND', [ true, 'The Redis command to run', 'INFO' ])
      ]
    )
  end

  def command
    datastore['COMMAND']
  end

  def run_host(_ip)
    vprint_status("Contacting redis")
    begin
      connect
      return unless (data = redis_command(command))
      report_service(host: rhost, port: rport, name: "redis server", info: "#{command} response: #{data}")
      print_good("Found redis with #{command} command: #{Rex::Text.to_hex_ascii(data)}")
    rescue Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout,
           Rex::ConnectionRefused, ::Timeout::Error, ::EOFError, ::Errno::ETIMEDOUT => e
      vprint_error("Error while communicating: #{e}")
    ensure
      disconnect
    end
  end
end
