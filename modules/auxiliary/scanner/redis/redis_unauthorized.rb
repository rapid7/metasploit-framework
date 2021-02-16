##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Redis
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Redis Unauthorized Scanner',
      'Description'  => %q(
        This module finds Redis Unauthorized vulnerability.
      ),
      'Author'       => [ 'weaponmaster3070@gmail.com', 'whale3070' ],
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
      connect  #Establishes a TCP connection to the specified RHOST/RPORT
      return unless (data = redis_command(command))
      #puts data
      if data["redis_version"]
          report_service(host: rhost, port: rport, name: "redis server", info: "#{command} response: #{data}") #store in the msf database
          print_good("Found redis with #{command} command: #{Rex::Text.to_hex_ascii(data)}")
      else
          vprint_error('Not found redis_Unauthorized')
      end

    rescue Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout,
           Rex::ConnectionRefused, ::Timeout::Error, ::EOFError, ::Errno::ETIMEDOUT => e
      vprint_error("Error while communicating: #{e}")
    ensure
      disconnect
    end
  end
end
