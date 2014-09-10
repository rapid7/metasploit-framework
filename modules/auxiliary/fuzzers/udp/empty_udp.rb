##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'UDP Empty Prober',
      'Description' => 'Detect UDP services that reply to empty probes',
      'Author'      => 'jon_hart[at]rapid7.com',
      'License'     => MSF_LICENSE
    )
    register_options([
      OptString.new('PORTS', [true, "Ports to probe", "1-1024,1194,2000,2049,4353,5060,5061,5351,8443"])
    ], self.class)
  end

  def setup
    @ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    fail_with(Msf::OptionValidateError.new(['PORTS'])) if @ports.empty?
  end

  def scanner_prescan(batch)
    print_status("Sending #{@ports.length} probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  def scan_host(ip)
    @ports.each do |port|
      scanner_send('', ip, port)
    end
  end

  def scanner_postscan(_batch)
    @results.each_key do |_k|
    end
  end

  def scanner_process(data, shost, sport)
    print_good("Received #{data.inspect} from #{shost}:#{sport}/udp")
  end
end
