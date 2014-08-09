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
      'Name'        => 'NTP PEER_LIST_SUM DoS Scanner',
      'Description' => %q{
        This module identifies NTP servers which permit "PEER_LIST_SUM" queries and
        return responses that are larger in size or greater in quantity than
        the request, allowing remote attackers to cause a denial of service
        (traffic amplification) via spoofed requests.
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
    @request_code = 1
    @probe = Rex::Proto::NTP.ntp_private(@version, @implementation, @request_code)
    vprint_status("Sending probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      packets = @results[k]
      # TODO: check to see if any of the responses are actually NTP before reporting
      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :name  => 'ntp'
      )
    end
  end
end
