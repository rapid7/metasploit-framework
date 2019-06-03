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
      'Name'        => 'Lantronix Telnet Service Banner Detection',
      'Description' => 'Detect Lantronix telnet services',
      'Author'      => ['theLightCosine', 'hdm'],
      'License'     => MSF_LICENSE
    )
    register_options(
    [
      Opt::RPORT(9999),
      OptInt.new('TIMEOUT', [true, 'Timeout for the Telnet probe', 30])
    ])

    deregister_options('USERNAME','PASSWORD')
  end

  def to
    return 30 if datastore['TIMEOUT'].to_i.zero?
    datastore['TIMEOUT'].to_i
  end

  def run_host(ip)
    begin
      ::Timeout.timeout(to) do
        res = connect
        if banner.start_with? "MAC address"
          print_good("#{ip}:#{rport} TELNET: #{banner}")
          version = banner.match(/Software version [\w\.]+ \(\d+\) \w*$/)[0]
          report_service(:host => rhost, :port => rport, :name => "telnet", :info => "Lantronix Version: #{version}" )
        end
      end
    rescue ::Rex::ConnectionError
    rescue Timeout::Error
      print_error("#{target_host}:#{rport}, Server timed out after #{to} seconds. Skipping.")
    rescue ::Exception => e
      print_error("#{e} #{e.backtrace}")
    end
  end
end
