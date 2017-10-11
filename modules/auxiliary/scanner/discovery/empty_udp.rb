##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'UDP Empty Prober',
      'Description' => 'Detect UDP services that reply to empty probes',
      'Author'      => 'Jon Hart <jon_hart[at]rapid7.com>',
      'License'     => MSF_LICENSE
    )
    register_options([
      OptString.new('PORTS', [true, 'Ports to probe', '1-1024,1194,2000,2049,4353,5060,5061,5351,8443'])
    ])
  end

  def setup
    super
    @ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    raise Msf::OptionValidateError.new(['PORTS']) if @ports.empty?
  end

  def scanner_prescan(batch)
    print_status("Sending #{@ports.length} empty probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  def scan_host(ip)
    @ports.each do |port|
      scanner_send('', ip, port)
    end
  end

  def scanner_process(data, shost, sport)
    print_good("Received #{data.inspect} from #{shost}:#{sport}/udp")
    report_service(:host => shost, :port => sport, :proto => 'udp', :info => data.inspect)
  end
end
