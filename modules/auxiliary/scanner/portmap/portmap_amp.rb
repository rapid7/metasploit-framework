##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::DRDoS

  def initialize
    super(
      'Name'        => 'Portmapper Amplification Scanner',
      'Description' => %q{
        This module can be used to discover Portmapper services which can be used in an
        amplification DDoS attack against a third party.
      },
      'Author'      => ['xistence <xistence[at]0x90.nl>'],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2013-5211'], # see also scanner/ntp/ntp_monlist.rb
          ['URL', 'https://www.us-cert.gov/ncas/alerts/TA14-017A'],
          ['URL', 'http://blog.level3.com/security/a-new-ddos-reflection-attack-portmapper-an-early-warning-to-the-industry/']
        ],
    )

    register_options( [
      Opt::RPORT(111),
    ])
  end

  def rport
    datastore['RPORT']
  end

  def xid_summary
    @xid_summary ||= [Rex::Text::rand_text_numeric(8).to_i].pack('N')
  end

  def xid_dump
    @xid_dump ||= [Rex::Text::rand_text_numeric(8).to_i].pack('N')
  end

  def xid_metrics
    @xid_metrics ||= [Rex::Text::rand_text_numeric(8).to_i].pack('N')
  end

  def setup
    super

    # RPC DUMP (Program version: 3) request: rpcinfo -T udp -s <IP>
    @portmap_summary = ''
    @portmap_summary << xid_summary # Random ID
    @portmap_summary << "\x00\x00\x00\x00" # Message Type: 0 (Call)
    @portmap_summary << "\x00\x00\x00\x02" # RPC Version: 2
    @portmap_summary << "\x00\x01\x86\xa0" # Program: Portmap (10000)
    @portmap_summary << "\x00\x00\x00\x03" # Program version: 3
    @portmap_summary << "\x00\x00\x00\x04" # Procedure: DUMP (4)
    @portmap_summary << "\x00\x00\x00\x00" # Credentials Flavor: AUTH_NULL (0)
    @portmap_summary << "\x00\x00\x00\x00" # Credentials Length: 0
    @portmap_summary << "\x00\x00\x00\x00" # Verifier Flavor: AUTH_NULL (0)
    @portmap_summary << "\x00\x00\x00\x00" # Verifier Length: 0

    # RPC DUMP (Program version: 2) request: rpcinfo -T udp -p <IP>
    @portmap_dump = ''
    @portmap_dump << xid_dump # Random ID
    @portmap_dump << "\x00\x00\x00\x00" # Message Type: 0 (Call)
    @portmap_dump << "\x00\x00\x00\x02" # RPC Version: 2
    @portmap_dump << "\x00\x01\x86\xa0" # Program: Portmap (10000)
    @portmap_dump << "\x00\x00\x00\x02" # Program version: 2
    @portmap_dump << "\x00\x00\x00\x04" # Procedure: DUMP (4)
    @portmap_dump << "\x00\x00\x00\x00" # Credentials Flavor: AUTH_NULL (0)
    @portmap_dump << "\x00\x00\x00\x00" # Credentials Length: 0
    @portmap_dump << "\x00\x00\x00\x00" # Verifier Flavor: AUTH_NULL (0)
    @portmap_dump << "\x00\x00\x00\x00" # Verifier Length: 0

    # RPC GETSTAT request: rpcinfo -T udp -m <IP>
    @portmap_metrics = ''
    @portmap_metrics << xid_metrics # Random ID
    @portmap_metrics << "\x00\x00\x00\x00" # Message Type: 0 (Call)
    @portmap_metrics << "\x00\x00\x00\x02" # RPC Version: 2
    @portmap_metrics << "\x00\x01\x86\xa0" # Program: Portmap (10000)
    @portmap_metrics << "\x00\x00\x00\x04" # Program version: 4
    @portmap_metrics << "\x00\x00\x00\x0c" # Procedure: GETSTAT (12)
    @portmap_metrics << "\x00\x00\x00\x00" # Credentials Flavor: AUTH_NULL (0)
    @portmap_metrics << "\x00\x00\x00\x00" # Credentials Length: 0
    @portmap_metrics << "\x00\x00\x00\x00" # Verifier Flavor: AUTH_NULL (0)
    @portmap_metrics << "\x00\x00\x00\x00" # Verifier Length: 0
  end

  def scanner_prescan(batch)
    print_status("Sending Portmap RPC probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results_summary = {}
    @results_dump = {}
    @results_metrics = {}
  end

  def scan_host(ip)
    if spoofed?
      datastore['ScannerRecvWindow'] = 0
      scanner_spoof_send(@portmap_summary, ip, rport, datastore['SRCIP'], datastore['NUM_REQUESTS'])
      scanner_spoof_send(@portmap_dump, ip, rport, datastore['SRCIP'], datastore['NUM_REQUESTS'])
      scanner_spoof_send(@portmap_metrics, ip, rport, datastore['SRCIP'], datastore['NUM_REQUESTS'])
    else
      scanner_send(@portmap_summary, ip, rport)
      scanner_send(@portmap_dump, ip, rport)
      scanner_send(@portmap_metrics, ip, rport)
    end
  end

  def scanner_process(data, shost, sport)
    if data =~ /#{@xid_summary}\x00\x00\x00\x01/
      @results_summary[shost] ||= []
      @results_summary[shost] << data
    elsif data =~ /#{@xid_metrics}\x00\x00\x00\x01/
      @results_metrics[shost] ||= []
      @results_metrics[shost] << data
    elsif data =~ /#{@xid_dump}\x00\x00\x00\x01/
      @results_dump[shost] ||= []
      @results_dump[shost] << data
    else
      vprint_error("Skipping #{data.size}-byte non-Portmap response from #{shost}:#{sport}")
    end
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results_summary.keys.each do |k|
      response_map_summary = { @portmap_summary => @results_summary[k] }
      what = 'Portmap RPC DUMP (Program version: 3) amplification'
      report_result(k, what, response_map_summary)
    end

    @results_dump.keys.each do |k|
      response_map_dump = { @portmap_dump => @results_dump[k] }
      what = 'Portmap RPC DUMP (Program version: 2) amplification'
      report_result(k, what, response_map_dump)
    end

    @results_metrics.keys.each do |k|
      response_map_metrics = { @portmap_summary => @results_metrics[k] }
      what = 'Portmap RPC GETSTAT amplification'
      report_result(k, what, response_map_metrics)
    end
  end

  def report_result(host, attack, map)
    report_service(
      host: host,
      proto: 'udp',
      port: rport,
      name: 'portmap'
    )

    peer = "#{host}:#{rport}"
    vulnerable, proof = prove_amplification(map)
    if vulnerable
      print_good("#{peer} - Vulnerable to #{attack}: #{proof}")
      report_vuln(
        host: host,
        port: rport,
        proto: 'udp',
        name: attack,
        refs: references
      )
    else
      vprint_status("#{peer} - Not vulnerable to #{attack}: #{proof}")
    end
  end
end


