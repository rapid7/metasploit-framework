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
      'Name'        => 'Memcached Amplification Scanner',
      'Description' => %q{
          This module can be used to discover Memcached servers which expose the
          unrestricted UDP port 11211. A basic "stats" request is executed to check
          if an amplification attack is possible against a third party.
      },
      'Author'      =>
        [
          'Marek Majkowski', # Cloudflare blog and base payload
          'xistence <xistence[at]0x90.nl>' # Metasploit scanner module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
          [
            ['URL', 'https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/']
          ]
    )

    register_options( [
      Opt::RPORT(11211),
    ])
  end

  def rport
    datastore['RPORT']
  end

  def setup
    super

    # Memcached stats probe
    @memcached_probe = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
  end

  def scanner_prescan(batch)
    print_status("Sending Memcached stats probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  def scan_host(ip)
    if spoofed?
      datastore['ScannerRecvWindow'] = 0
      scanner_spoof_send(@memcached_probe, ip, datastore['RPORT'], datastore['SRCIP'], datastore['NUM_REQUESTS'])
    else
      scanner_send(@memcached_probe, ip, datastore['RPORT'])
    end
  end

  def scanner_process(data, shost, sport)

    # Check the response data for a "STAT" repsonse
    if data =~/\x00\x00\x00\x00\x00\x01\x00\x00STAT\x20/
      amp = data.length / @memcached_probe.length.to_f
      print_good("#{shost}:#{datastore['RPORT']} - Response is #{data.length} bytes [#{amp.round(2)}x Amplification]")
      report_service(:host => shost, :port => datastore['RPORT'], :proto => 'udp', :name => "memcached")
      report_vuln(
        :host => shost,
        :port => datastore['RPORT'],
        :proto => 'udp', :name => "MEMCACHED",
        :info => "MEMCACHED amplification -  #{data.length} bytes [#{amp.round(2)}x Amplification]",
        :refs => self.references)
    end
  end
end
