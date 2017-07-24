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
      'Name'           => 'NTP Mode 6 UNSETTRAP DRDoS Scanner',
      'Description'    => %q{
        This module identifies NTP servers which permit mode 6 UNSETTRAP requests that
        can be used to conduct DRDoS attacks.  In some configurations, NTP servers will
        respond to UNSETTRAP requests with multiple packets, allowing remote attackers
        to cause a distributed, reflected denial of service (aka, "DRDoS" or traffic
        amplification) via spoofed requests.
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
    @results[shost] << Rex::Proto::NTP::NTPControl.new.read(data)
  end

  # Called before the scan block
  def scanner_prescan(batch)
    @results = {}
    @probe = Rex::Proto::NTP::NTPControl.new
    @probe.version = datastore['VERSION']
    @probe.operation = 31
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
      what = 'R7-2014-12 NTP Mode 6 UNSETTRAP DRDoS'
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
