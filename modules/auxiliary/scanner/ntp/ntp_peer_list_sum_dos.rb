##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::NTP
  include Msf::Auxiliary::DRDoS

  def initialize
    super(
      'Name'           => 'NTP Mode 7 PEER_LIST_SUM DoS Scanner',
      'Description'    => %q{
        This module identifies NTP servers which permit "PEER_LIST_SUM" queries and
        return responses that are larger in size or greater in quantity than
        the request, allowing remote attackers to cause a distributed, reflected
        denial of service (aka, "DRDoS" or traffic amplification) via spoofed
        requests.
      },
      'Author'         => 'Jon Hart <jon_hart[at]rapid7.com>',
      'References'     =>
        [
          ['CVE', '2013-5211'], # see also scanner/ntp/ntp_monlist.rb
          ['URL', 'https://github.com/rapid7/metasploit-framework/pull/3696'],
          ['URL', 'http://r-7.co/R7-2014-12']
        ],
      'DisclosureDate' => 'Aug 25 2014',
      'License'        => MSF_LICENSE
    )
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
    @results[shost] ||= []
    @results[shost] << Rex::Proto::NTP::NTPPrivate.new.read(data).to_binary_s
  end

  # Called before the scan block
  def scanner_prescan(batch)
    @results = {}
    @probe = Rex::Proto::NTP.ntp_private(datastore['VERSION'], datastore['IMPLEMENTATION'], 1).to_binary_s
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      response_map = { @probe => @results[k] }
      # TODO: check to see if any of the responses are actually NTP before reporting
      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :name  => 'ntp'
      )

      peer = "#{k}:#{rport}"
      vulnerable, proof = prove_amplification(response_map)
      what = 'R7-2014-12 NTP Mode 7 PEER_LIST_SUM DRDoS'
      if vulnerable
        print_good("#{peer} - Vulnerable to #{what}: #{proof}")
        report_vuln({
          :host  => k,
          :port  => rport,
          :proto => 'udp',
          :name  => what,
          :refs  => self.references
        })
      else
        vprint_status("#{peer} - Not vulnerable to #{what}: #{proof}")
      end
    end
  end
end
