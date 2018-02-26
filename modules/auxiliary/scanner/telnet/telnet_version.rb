##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Telnet
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Telnet Service Banner Detection',
      'Description' => 'Detect telnet services',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )
    register_options(
    [
      Opt::RPORT(23),
      OptInt.new('TIMEOUT', [true, 'Timeout for the Telnet probe', 30])
    ])
  end

  def to
    return 30 if datastore['TIMEOUT'].to_i.zero?
    datastore['TIMEOUT'].to_i
  end

  def run_host(ip)
    begin
      ::Timeout.timeout(to) do
        res = connect
        # This makes db_services look a lot nicer.
        banner_santized = Rex::Text.to_hex_ascii(banner.to_s)
        print_good("#{ip}:#{rport} TELNET #{banner_santized}")
        report_service(:host => rhost, :port => rport, :name => "telnet", :info => banner_santized)
      end
    rescue ::Rex::ConnectionError, ::Errno::ECONNRESET => e
      print_error("A network issue has occurred: #{e.message}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    rescue Timeout::Error => e
      print_error("#{target_host}:#{rport}, Server timed out after #{to} seconds. Skipping.")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    rescue ::Exception => e
      print_error("#{e} #{e.backtrace}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end
  end
end
