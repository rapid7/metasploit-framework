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
      'Name'        => 'Memcached Stats Amplification Scanner',
      'Description' => %q(
          This module can be used to discover Memcached servers which expose the
          unrestricted UDP port 11211. A basic "stats" request is executed to check
          if an amplification attack is possible against a third party.
      ),
      'Author'      =>
        [
          'Marek Majkowski', # Cloudflare blog and base payload
          'xistence <xistence[at]0x90.nl>', # Metasploit scanner module
          'Jon Hart <jon_hart@rapid7.com>', # Metasploit scanner module
        ],
      'License'     => MSF_LICENSE,
      'DisclosureDate' => 'Feb 27, 2018',
      'References'  =>
          [
            ['URL', 'https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/'],
            ['CVE', '2018-1000115']
          ]
    )

    register_options([
      Opt::RPORT(11211)
    ])
  end

  def build_probe
    # Memcached stats probe, per https://github.com/memcached/memcached/blob/master/doc/protocol.txt
    @memcached_probe ||= [
      rand(2**16), # random request ID
      0, # sequence number
      1, # number of datagrams in this sequence
      0, # reserved; must be 0
      "stats\r\n"
    ].pack("nnnna*")
  end

  def scanner_process(data, shost, sport)
    # Check the response data for a "STAT" repsonse
    if data =~ /\x0d\x0aSTAT\x20/
      @results[shost] ||= []
      @results[shost] << data
    end
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |host|
      response_map = { @memcached_probe => @results[host] }
      report_service(
        host: host,
        proto: 'udp',
        port: rport,
        name: 'memcached'
      )

      peer = "#{host}:#{rport}"
      vulnerable, proof = prove_amplification(response_map)
      what = 'memcached stats amplification'
      if vulnerable
        print_good("#{peer} - Vulnerable to #{what}: #{proof}")
        report_vuln(
          host: host,
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
