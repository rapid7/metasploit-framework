##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::NTP

  def initialize
    super(
      'Name'        => 'NTP GET_RESTRICT DoS Scanner',
      'Description' => %q{
        This module identifies NTP servers which permit "reslist" queries and
        obtains the list of restrictions placed on various network interfaces,
        networks or hosts.  The reslist feature allows remote
        attackers to cause a denial of service (traffic amplification) via
        spoofed requests. The more interfaces, networks or host with specific
        restrictions, the greater the amplification.
      },
      'References'  =>
        [
        ],
      'Author'      => 'Jon Hart <jon_hart[at]rapid7.com>',
      'License'     => MSF_LICENSE
    )
  end

  # Called for each IP in the batch
  def scan_host(ip)
    scanner_send(@probe, ip, datastore['RPORT'])
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
    @results[shost] ||= []
    @results[shost] << Rex::Proto::NTP::NTPPrivate.new(data)
  end

  # Called before the scan block
  def scanner_prescan(batch)
    @results = {}
    @version = 2
    @implementation = 3
    @request_code = 16
    @probe = Rex::Proto::NTP.ntp_private(@version, @implementation, @request_code)
    vprint_status("Sending probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      packets = @results[k]
      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :name  => 'ntp'
      )
    end
  end
end
