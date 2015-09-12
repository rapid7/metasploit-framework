##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::DRDoS

  XID_SUMMARY = [Rex::Text::rand_text_numeric(8).to_i].pack("N")
  XID_METRICS = [Rex::Text::rand_text_numeric(8).to_i].pack("N")
  XID_DUMP = [Rex::Text::rand_text_numeric(8).to_i].pack("N")

  def initialize
    super(
      'Name'        => 'Portmap Amplification Scanner',
      'Description' => %q{
          This module can be used to discover Portmap servers which expose unauthicated
          functionality that can be used in an amplication attack against a third party.
      },
      'Author'      => [ 'xistence <xistence[at]0x90.nl>'], # Original scanner module
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'https://www.us-cert.gov/ncas/alerts/TA14-017A']
        ],
    )

    register_options( [
      Opt::RPORT(111),
    ], self.class)
  end

  def rport
    datastore['RPORT']
  end

  def setup
    super

    # RPC DUMP (Program version: 3) request: rpcinfo -T udp -s <IP>
    @portmap_summary = ""
    @portmap_summary << XID_SUMMARY # Random ID
    @portmap_summary << "\x00\x00\x00\x00" # Message Type: 0 (Call)
    @portmap_summary << "\x00\x00\x00\x02" # RPC Version: 2
    @portmap_summary << "\x00\x01\x86\xa0" # Program: Portmap (10000)
    @portmap_summary << "\x00\x00\x00\x03" # Program version: 3
    @portmap_summary << "\x00\x00\x00\x04" # Procedure: DUMP (4)
    @portmap_summary << "\x00\x00\x00\x00" # Credentials Flavor: AUTH_NULL (0)
    @portmap_summary << "\x00\x00\x00\x00" # Credentials Length: 0
    @portmap_summary << "\x00\x00\x00\x00" # Verifier Flavor: AUTH_NULL (0)
    @portmap_summary << "\x00\x00\x00\x00" # Verifier Length: 0

    # RPC DUMP (Program version: 3) request: rpcinfo -T udp -p <IP>
    @portmap_dump = ""
    @portmap_dump << XID_DUMP # Random ID
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
    @portmap_metrics = ""
    @portmap_metrics << XID_METRICS # Random ID
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
      scanner_spoof_send(@portmap_summary, ip, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
      scanner_spoof_send(@portmap_dump, ip, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
      scanner_spoof_send(@portmap_metrics, ip, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
    else
      scanner_send(@portmap_summary, ip, datastore['RPORT'])
      scanner_send(@portmap_dump, ip, datastore['RPORT'])
      scanner_send(@portmap_metrics, ip, datastore['RPORT'])
    end
  end

  def scanner_process(data, shost, sport)
    if data =~/#{XID_SUMMARY}\x00\x00\x00\x01/
      @results_summary[shost] ||= []
      @results_summary[shost] << data
    elsif data =~/#{XID_METRICS}\x00\x00\x00\x01/
      @results_metrics[shost] ||= []
      @results_metrics[shost] << data
    elsif data =~/#{XID_DUMP}\x00\x00\x00\x01/
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

      report_service(
        host: k,
        proto: 'udp',
        port: datastore['RPORT'],
        name: 'portmap'
      )

      peer = "#{k}:#{datastore['RPORT']}"
      vulnerable, proof = prove_amplification(response_map_summary)
      what = 'Portmap RPC DUMP (Program version: 3) amplification'
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

    @results_dump.keys.each do |k|
      response_map_dump = { @portmap_dump => @results_dump[k] }

      report_service(
        host: k,
        proto: 'udp',
        port: datastore['RPORT'],
        name: 'portmap'
      )

      peer = "#{k}:#{datastore['RPORT']}"
      vulnerable, proof = prove_amplification(response_map_dump)
      what = 'Portmap RPC DUMP (Program version: 2) amplification'
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

    @results_metrics.keys.each do |k|
      response_map_metrics = { @portmap_summary => @results_metrics[k] }

      report_service(
        host: k,
        proto: 'udp',
        port: datastore['RPORT'],
        name: 'portmap'
      )

      peer = "#{k}:#{datastore['RPORT']}"
      vulnerable, proof = prove_amplification(response_map_metrics)
      what = 'Portmap RPC GETSTAT amplification'
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


