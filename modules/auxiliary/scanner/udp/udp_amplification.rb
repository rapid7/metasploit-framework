##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::DRDoS
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'UDP Amplification Scanner',
      'Description' => 'Detect UDP endpoints with UDP amplification vulnerabilities',
      'Author'      => 'Jon Hart <jon_hart[at]rapid7.com>',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2013-5211'], # see also scanner/ntp/ntp_monlist.rb
          ['URL', 'https://www.us-cert.gov/ncas/alerts/TA14-017A']
        ]
    )

    register_options(
      [
        OptString.new('PORTS', [true, 'Ports to probe']),
        OptString.new('PROBE', [false, 'UDP payload/probe to send.  Unset for an empty UDP datagram, or the `file://` resource to get content from a local file'])
      ]
    )

    # RPORT is unused in this scanner module because it supports multiple ports
    deregister_options('RPORT')
  end

  def setup
    super

    unless (@ports = Rex::Socket.portspec_crack(datastore['PORTS']))
      fail_with(Failure::BadConfig, "Unable to extract list of ports from #{datastore['PORTS']}")
    end

    @probe = datastore['PROBE'] ? datastore['PROBE'] : ''
  end

  def scanner_prescan(batch)
    print_status("Sending #{@probe.length}-byte probes to #{@ports.length} port(s) on #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results ||= {}
  end

  def scan_host(ip)
    @ports.each do |port|
      scanner_send(@probe, ip, port)
    end
  end

  # Called for each response packet, overriding UDPScanner's so that we can
  # store all responses on a per-host, per-port basis
  def scanner_process(data, shost, sport)
    @results[shost] ||= {}
    @results[shost][sport] ||= []
    @results[shost][sport] << data
  end

  def scanner_postscan(batch)
    batch.each do |shost|
      next unless @results.key?(shost)
      @results[shost].each_pair do |sport, responses|
        report_service(host: shost, port: sport, proto: 'udp', info: responses.inspect, state: 'open')
        vulnerable, proof = prove_amplification(@probe => responses)
        next unless vulnerable
        print_good("#{shost}:#{sport} - susceptible to UDP amplification: #{proof}")
        report_vuln(
          host: shost,
          port: sport,
          proto: 'udp',
          name: 'UDP amplification',
          refs: references
        )
      end
    end
  end
end
