##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::DRDoS

  def initialize
    super(
      'Name'        => 'SSDP ssdp:all M-SEARCH Amplification Scanner',
      'Description' => 'Discover SSDP amplification possibilities',
      'Author'      => ['xistence <xistence[at]0x90.nl>'], # Original scanner module
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2013-5211'], # see also scanner/ntp/ntp_monlist.rb
          ['URL', 'https://www.us-cert.gov/ncas/alerts/TA14-017A']
        ],
    )

    register_options([
      Opt::RPORT(1900),
      OptBool.new('SHORT', [ false, "Does a shorter request, for a higher amplifier, not compatible with all devices", false])
    ])
  end

  def setup
    super
    # SSDP packet containing the "ST:ssdp:all" search query
    if datastore['short']
      # Short packet doesn't contain Host, MX and last \r\n
      @msearch_probe = "M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\nMan: \"ssdp:discover\"\r\n"
    else
      @msearch_probe = "M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\nMan: \"ssdp:discover\"\r\nMX: 1\r\n\r\n"
    end
  end

  def scanner_prescan(batch)
    print_status("Sending SSDP ssdp:all M-SEARCH probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  def scan_host(ip)
    if spoofed?
      datastore['ScannerRecvWindow'] = 0
      scanner_spoof_send(@msearch_probe, ip, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
    else
      scanner_send(@msearch_probe, ip, datastore['RPORT'])
    end
  end

  def scanner_process(data, shost, sport)
    if data =~ /HTTP\/\d\.\d 200/
      @results[shost] ||= []
      @results[shost] << data
    else
      vprint_error("Skipping #{data.size}-byte non-SSDP response from #{shost}:#{sport}")
    end
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      response_map = { @msearch_probe => @results[k] }
      report_service(
        host: k,
        proto: 'udp',
        port: datastore['RPORT'],
        name: 'ssdp'
      )

      peer = "#{k}:#{datastore['RPORT']}"
      vulnerable, proof = prove_amplification(response_map)
      what = 'SSDP ssdp:all M-SEARCH amplification'
      if vulnerable
        print_good("#{peer} - Vulnerable to #{what}: #{proof}")
        report_vuln(
          host: k,
          port: datastore['RPORT'],
          proto: 'udp',
          name: what,
          refs: self.references
        )
      else
        vprint_status("#{peer} - Not vulnerable to #{what}: #{proof}")
      end
    end
  end
end
