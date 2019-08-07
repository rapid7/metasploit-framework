##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  require 'rc4'
  include Msf::Exploit::Remote::Tcp
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
      },
      'Author'         =>
        [
          'National Cyber Security Centre', # Discovery
          'JaGoTu',                         # Module
          'zerosum0x0',                     # Module
          'Tom Sellers'                     # TLS support and documented packets
        ],
      'References'     =>
        [
          [ 'CVE', '2019-0708' ],
          [ 'URL', 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708' ]
        ],
      'DisclosureDate' => '2019-05-14',
      'License'        => MSF_LICENSE,
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
      print_status("The target service is not running, or refused our connection.")
    else
      print_status(status[1].to_s)
    end

    status
  end

  def check_host(ip)
    # The check command will call this method instead of run_host

    status = Exploit::CheckCode::Unknown

    begin
      begin
        nsock = connect
      rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
        return Exploit::CheckCode::Unsupported # used to display custom msg error
      end

      status = Exploit::CheckCode::Detected

      sock.setsockopt(::Socket::IPPROTO_TCP, ::Socket::TCP_NODELAY, 1)
      status = check_rdp_vuln(nsock)
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
      disconnect
    end

    status
  end

  def check_for_patch
    begin
      for i in 0..5
        res = rdp_recv
      end
    rescue RdpCommunicationError
      # we don't care
    end

    # The loop below sends Virtual Channel PDUs (2.2.6.1) that vary in length
    # The arch governs which of the packets triggers the desired response
    # which is an MCS Disconnect Provider Ultimatum or a timeout.

    # 0x03 = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST
    x86_payload = build_virtual_channel_pdu(0x03, ["00000000020000000000000000000000"].pack("H*"))
    x64_payload = build_virtual_channel_pdu(0x03, ["0000000000000000020000000000000000000000000000000000000000000000"].pack("H*"))

    vprint_status("Sending patch check payloads")
    for j in 0..5

      # 0xed03 = Channel 1005
      x86_packet = rdp_build_pkt(x86_payload, "\x03\xed")
      rdp_send(x86_packet)
      x64_packet = rdp_build_pkt(x64_payload, "\x03\xed")
      rdp_send(x64_packet)

      # Quick check for the Ultimatum PDU
      begin
        res = sock.get_once(-1, 1)
      rescue EOFError
        # we don't care
      end
      return Exploit::CheckCode::Vulnerable if res && res.include?(["0300000902f0802180"].pack("H*"))

      # Slow check for Ultimatum PDU. If it doesn't respond in a timely
      # manner then the host is likely patched.
      begin
        for i in 0..3
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

  def check_rdp_vuln(nsock)
    # check if rdp is open
    is_rdp, server_selected_proto = rdp_negotiate_protocol
    unless is_rdp
      vprint_status "Could not connect to RDP."
      return Exploit::CheckCode::Unknown
    end

    if server_selected_proto == 1
      vprint_status("Server requests TLS")
      swap_sock_plain_to_ssl(nsock)

      # send initial client data
      res = rdp_send_recv(pdu_connect_initial(server_selected_proto, @computer_name))
    elsif server_selected_proto == 0
      vprint_status("Server requests RDP Security")
      # send initial client data
      res = rdp_send_recv(pdu_connect_initial(server_selected_proto, @computer_name))
      rsmod, rsexp, _rsran, server_rand, bitlen = rdp_parse_connect_response(res)
    elsif [RDPConstants::PROTOCOL_HYBRID, RDPConstants::PROTOCOL_HYBRID_EX].include? server_selected_proto
      vprint_status("Server requires NLA (CredSSP) security which mitigates this vulnerability.")
      return Exploit::CheckCode::Safe
    else
      vprint_status("Server requests an unhandled protocol (#{server_selected_proto.to_s}), status unknown.")
      return Exploit::CheckCode::Unknown
    end

    # erect domain and attach user
    vprint_status("Sending erect domain request")
    rdp_send(pdu_erect_domain_request)
    res = rdp_send_recv(pdu_attach_user_request)

    user1 = res[9, 2].unpack("n").first

    # send channel requests
    [1009, 1003, 1004, 1005, 1006, 1007, 1008].each do |chan|
      rdp_send_recv(pdu_channel_request(user1, chan))
    end

    if server_selected_proto == 0
      @rdp_sec = true

      # 5.3.4 Client Random Value
      client_rand = ''
      32.times { client_rand << rand(0..255) }
      rcran = bytes_to_bignum(client_rand)

      vprint_status("Sending security exchange PDU")
      rdp_send(pdu_security_exchange(rcran, rsexp, rsmod, bitlen))

      # We aren't decrypting anything at this point. Leave the variables here
      # to make it easier to understand in the future.
      rc4encstart, _rc4decstart, @hmackey, _sessblob = rdp_calculate_rc4_keys(client_rand, server_rand)

      @rc4enckey = RC4.new(rc4encstart)
    end

    vprint_status("Sending client info PDU")
    res = rdp_send_recv(rdp_build_pkt(pdu_client_info(@user_name, @domain, @ip_address), "\x03\xeb", true))
    vprint_status("Received License packet")

    # Windows XP sometimes sends a very large license packet. This is likely
    # some form of license error. When it does this it doesn't send a Server
    # Demand packet. If we wait on one we will time out here and error. We
    # can still successfully check for vulnerability anyway.
    if res.length <= 34
      vprint_status("Waiting for Server Demand packet")
      _res = rdp_recv
      vprint_status("Received Server Demand packet")
    end

    vprint_status("Sending client confirm active PDU")
    rdp_send(rdp_build_pkt(pdu_client_confirm_active))

    vprint_status("Sending client synchronize PDU")
    vprint_status("Sending client control cooperate PDU")
    # Unsure why we're using 1009 here but it works.
    synch = rdp_build_pkt(pdu_client_synchronize(1009))
    coop = rdp_build_pkt(pdu_client_control_cooperate)
    rdp_send(synch + coop)

    vprint_status("Sending client control request control PDU")
    rdp_send(rdp_build_pkt(pdu_client_control_request))

    vprint_status("Sending client input sychronize PDU")
    rdp_send(rdp_build_pkt(pdu_client_input_event_sychronize))

    vprint_status("Sending client font list PDU")
    rdp_send(rdp_build_pkt(pdu_client_font_list))

    result = check_for_patch

    if result == Exploit::CheckCode::Vulnerable
      report_goods
    end

    # Can't determine, but at least I know the service is running
    result
  end

end
