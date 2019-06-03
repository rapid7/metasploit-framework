##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
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
          'JaGoTu',
          'zerosum0x0',
          'Tom Sellers'
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

    register_options(
      [
        Opt::RPORT(3389)
      ])
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
      print_status("#{status[1]}")
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
    rescue Errno::ECONNRESET  # NLA?
      vprint_error("Connection reset, possible NLA is enabled.")
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

  def check_rdp

    # code to check if RDP is open or not
    vprint_status("Verifying RDP protocol...")

    vprint_status("Attempting to connect using TLS security")
    res = rdp_send_recv(pdu_negotiation_request(RDPConstants::PROTOCOL_SSL))

    # return true if the response is a X.224 Connect Confirm
    # We can't use a check for RDP Negotiation Response because WinXP excludes it
    if res
      result, err_msg = rdp_parse_negotiation_response(res)
      return true, result if result

      if err_msg == "Negotiation Response packet too short."
        vprint_status("Attempt to connect with TLS failed but looks like the target is Windows XP")
      else
        vprint_status("Attempt to connect with TLS failed with error: #{err_msg}")
      end

      if ["SSL_NOT_ALLOWED_BY_SERVER", "Negotiation Response packet too short."].include? err_msg
        # This happens if the server is configured to ONLY permit RDP Security
        vprint_status("Attempting to connect using Standard RDP security")
        disconnect
        connect
        res = rdp_send_recv(pdu_negotiation_request(RDPConstants::PROTOCOL_RDP))

        if res
          result, err_msg = rdp_parse_negotiation_response(res)
          return true, result if result

          # Windows XP doesn't return the standard Negotiation Response packet
          # but we at least know this was RDP since the packet contained a 
          # Connect-Confirm response (0xd0).
          if err_msg == "Negotiation Response packet too short."
            return true, RDPConstants::PROTOCOL_RDP
          end

          vprint_status("Attempt to connect with Standard RDP failed with error #{err_msg}")
        end
      end
    end

    return false, 0
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
    # The arch governs which triggers the desired response which is a MCS
    # Disconnect Provider Ultimatum or a timeout.
    for j in 0..5
      # x86
      pkt = rdp_build_pkt(["100000000300000000000000020000000000000000000000"].pack("H*"), "\x03\xed")
      rdp_send(pkt)
      # x64
      pkt = rdp_build_pkt(["20000000030000000000000000000000020000000000000000000000000000000000000000000000"].pack("H*"), "\x03\xed")
      rdp_send(pkt)

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
    is_rdp, server_selected_proto = check_rdp
    unless is_rdp
      vprint_status "Could not connect to RDP."
      return Exploit::CheckCode::Unknown
    end

    if server_selected_proto == 1
      vprint_status("Server requests TLS")
      swap_sock_plain_to_ssl(nsock)

      # send initial client data
      res = rdp_send_recv(pdu_connect_initial(server_selected_proto))
    elsif server_selected_proto == 0
      vprint_status("Server requests RDP Security")
      # send initial client data
      res = rdp_send_recv(pdu_connect_initial(server_selected_proto))
      rsmod, rsexp, rsran, server_rand, bitlen = rdp_parse_connect_response(res)
    else
      vprint_status("Server requests NLA security which mitigates this vulnerability.")
      return Exploit::CheckCode::Safe
    end

    # erect domain and attach user
    vprint_status("Sending erect domain request")
    rdp_send(pdu_erect_domain_request)
    res = rdp_send_recv(pdu_attach_user_request)

    user1 = res[9,2].unpack("n").first

    # send channel requests
    [1009, 1003, 1004, 1005, 1006, 1007, 1008].each do |chan|
      rdp_send_recv(pdu_channel_request(user1, chan))
    end

    if server_selected_proto == 0
      @rdp_sec = true

      client_rand = "\x41" * 32
      rcran = bytes_to_bignum(client_rand)

      vprint_status("Sending security exchange PDU")
      rdp_send(pdu_security_exchange(rcran, rsexp, rsmod, bitlen))

      rc4encstart, rc4decstart, @hmackey, sessblob = rdp_calculate_rc4_keys(client_rand, server_rand)

      @rc4enckey = RC4.new(rc4encstart)
    end

    vprint_status("Sending client info PDU")
    res = rdp_send_recv(rdp_build_pkt(pdu_client_info, "\x03\xeb", true))
    vprint_status("Received License packet")

    res = rdp_recv
    vprint_status("Received Server Demand packet")

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

    vprint_status("Sending client persistent key list PDU")
    rdp_send(rdp_build_pkt(pdu_client_persistent_key_list))

    vprint_status("Sending client font list PDU")
    rdp_send(rdp_build_pkt(pdu_client_font_list))

    result = check_for_patch

    if result == Exploit::CheckCode::Vulnerable
      report_goods
    end

    # Can't determine, but at least I know the service is running
    result
  end

  # Create a new SSL session on the existing socket.
  # Stolen from exploit/smtp_deliver.rb
  def swap_sock_plain_to_ssl(nsock)
    ctx = OpenSSL::SSL::SSLContext.new
    ssl = OpenSSL::SSL::SSLSocket.new(nsock, ctx)

    ssl.connect

    nsock.extend(Rex::Socket::SslTcp)
    nsock.sslsock = ssl
    nsock.sslctx  = ctx
  end


  #
  # Standard RDP
  # Communication and parsing functions
  #

  # used to abruptly abort scanner for a given host
  class RdpCommunicationError < StandardError
  end

   #
  # Standard RDP
  # Constants
  #
  class RDPConstants
    SSL_REQUIRED_BY_SERVER = 1
    SSL_NOT_ALLOWED_BY_SERVER = 2
    SSL_CERT_NOT_ON_SERVER = 3
    INCONSISTENT_FLAGS =  4
    HYBRID_REQUIRED_BY_SERVER = 5
    SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6

    PROTOCOL_RDP = 0
    PROTOCOL_SSL = 1
    PROTOCOL_HYBRID = 2
    PROTOCOL_RDSTLS = 4
    PROTOCOL_HYBRID_EX = 8

    RDP_NEG_PROTOCOL = {
      0 => "PROTOCOL_RDP",
      1 => "PROTOCOL_SSL",
      2 => "PROTOCOL_HYBRID",
      4 => "PROTOCOL_RDSTLS",
      8 => "PROTOCOL_HYBRID_EX"
    }

    RDP_NEG_FAILURE = {
      1 => "SSL_REQUIRED_BY_SERVER",
      2 => "SSL_NOT_ALLOWED_BY_SERVER",
      3 => "SSL_CERT_NOT_ON_SERVER",
      4 => "INCONSISTENT_FLAGS",
      5 => "HYBRID_REQUIRED_BY_SERVER",
      6 => "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
    }
  end

  def rdp_send(data)
    sock.put(data)
  end

  def rdp_recv
    res = sock.get_once(-1, 5)
    raise RdpCommunicationError unless res # nil due to a timeout

    res
  end

  def rdp_send_recv(data)
    rdp_send(data)
    rdp_recv
  end

  # Build the X.224 packet, encrypt with Standard RDP Security as needed
  def rdp_build_pkt(data, channel_id = "\x03\xeb", client_info = false)

    flags = 0
    flags |= 0b1000 if @rdp_sec       # Set SEC_ENCRYPT
    flags |= 0b1000000 if client_info # Set SEC_INFO_PKT

    pdu = ""

    # TS_SECURITY_HEADER - 2.2.8.1.1.2.1
    # Send when the packet is encrypted w/ Standard RDP Security and in all Client Info PDUs
    if client_info || @rdp_sec
      pdu << [flags].pack("S<")  # flags  "\x48\x00" = SEC_INFO_PKT | SEC_ENCRYPT
      pdu << "\x00\x00"          # flagsHi
    end

    if @rdp_sec
      # Encrypt the payload with RDP Standard Encryption
      pdu << rdp_hmac(@hmackey, data)[0..7]
      pdu << rdp_rc4_crypt(@rc4enckey, data)
    else
      pdu << data
    end

    user_data_len = pdu.length
    udl_with_flag = 0x8000 | user_data_len

    pkt =  "\x64"      # sendDataRequest
    pkt << "\x00\x08"  # intiator userId .. TODO: for a functional client this isn't static
    pkt << channel_id  # channelId = 1003
    pkt << "\x70"      # dataPriority
    pkt << [udl_with_flag].pack("S>")
    pkt << pdu

    build_data_tpdu(pkt)
  end

  # Parse RDP Negotiation Data - 2.2.1.2
  # Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483
  # @return [String, nil] String representation of the Selected Protocol or nil on failure
  # @return [String] Error message
  def rdp_parse_negotiation_response(data)

    return false, "Response is not an RDP Negotiation Response packet." unless data.match("\x03\x00\x00..\xd0")
    return false, "Negotiation Response packet too short." if data.length < 19

    response_code = data[11].unpack("C")[0]

    if response_code == 2  # TYPE_RDP_NEG_RSP
      # RDP Negotiation Response - 2.2.1.2.1
      server_selected_proto = data[15..18].unpack("L<")[0]

      proto_label = RDPConstants::RDP_NEG_PROTOCOL[server_selected_proto]
      return server_selected_proto, nil if proto_label

      return nil, "Unknown protocol in Negotiation Response: #{server_selected_proto.to_s}"

    elsif response_code == 3  # TYPE_RDP_NEG_FAILURE
      # RDP Negotiation Failure - 2.2.1.2.2
      failure_code = data[15..18].unpack("L<")[0]
      return nil, RDPConstants::RDP_NEG_FAILURE[failure_code]
    else
      return nil, "Unknown Negotiation Response code: #{response_code.to_s}"
    end
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c
  # Parse Server MCS Connect Response PUD - 2.2.1.4
  def rdp_parse_connect_response(pkt)
    ptr = 0
    rdp_pkt = pkt[0x49..pkt.length]

    while ptr < rdp_pkt.length
      header_type = rdp_pkt[ptr..ptr + 1]
      header_length = rdp_pkt[ptr + 2..ptr + 3].unpack("S<")[0]

      if header_type == "\x02\x0c"

        server_random = rdp_pkt[ptr + 20..ptr + 51]
        public_exponent = rdp_pkt[ptr + 84..ptr + 87]

        rsa_magic = rdp_pkt[ptr + 68..ptr + 71]
        if rsa_magic != "RSA1"
          print_error("Server cert isn't RSA, this scenario isn't supported (yet).")
          raise RdpCommunicationError
        end

        bitlen = rdp_pkt[ptr + 72..ptr + 75].unpack("L<")[0] - 8
        modulus = rdp_pkt[ptr + 88..ptr + 87 + bitlen]
      end

      ptr += header_length
    end

    # vprint_status("SERVER_MODULUS: #{bin_to_hex(modulus)}")
    # vprint_status("SERVER_EXPONENT: #{bin_to_hex(public_exponent)}")
    # vprint_status("SERVER_RANDOM: #{bin_to_hex(server_random)}")

    rsmod = bytes_to_bignum(modulus)
    rsexp = bytes_to_bignum(public_exponent)
    rsran = bytes_to_bignum(server_random)

    # vprint_status("MODULUS  = #{bin_to_hex(modulus)} - #{rsmod.to_s}")
    # vprint_status("EXPONENT = #{bin_to_hex(public_exponent)} - #{rsexp.to_s}")
    # vprint_status("SVRANDOM = #{bin_to_hex(server_random)} - #{rsran.to_s}")

    return rsmod, rsexp, rsran, server_random, bitlen
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7c61b54e-f6cd-4819-a59a-daf200f6bf94
  # mac_salt_key = "W\x13\xc58\x7f\xeb\xa9\x10*\x1e\xddV\x96\x8b[d"
  # data_content = "\x12\x00\x17\x00\xef\x03\xea\x03\x02\x00\x00\x01\x04\x00$\x00\x00\x00"
  # hmac = rdp_hmac(mac_salt_key, data_content) # == hexlified: "22d5aeb486994a0c785dc929a2855923"
  def rdp_hmac(mac_salt_key, data_content)
    sha1 = Digest::SHA1.new
    md5 = Digest::MD5.new

    pad1 = "\x36" * 40
    pad2 = "\x5c" * 48

    sha1 << mac_salt_key
    sha1 << pad1
    sha1 << [data_content.length].pack('<L')
    sha1 << data_content

    md5 << mac_salt_key
    md5 << pad2
    md5 << [sha1.hexdigest].pack("H*")

    [md5.hexdigest].pack("H*")
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
  #  SaltedHash(S, I) = MD5(S + SHA(I + S + ClientRandom + ServerRandom))
  def rdp_salted_hash(s_bytes, i_bytes, client_random_bytes, server_random_bytes)
    sha1 = Digest::SHA1.new
    md5 = Digest::MD5.new

    sha1 << i_bytes
    sha1 << s_bytes
    sha1 << client_random_bytes
    sha1 << server_random_bytes

    md5 << s_bytes
    md5 << [sha1.hexdigest].pack("H*")

    [md5.hexdigest].pack("H*")
  end

  #  FinalHash(K) = MD5(K + ClientRandom + ServerRandom)
  def rdp_final_hash(k, client_random_bytes, server_random_bytes)
    md5 = Digest::MD5.new

    md5 << k
    md5 << client_random_bytes
    md5 << server_random_bytes

    [md5.hexdigest].pack("H*")
  end

  def rdp_calculate_rc4_keys(client_random, server_random)
    # preMasterSecret = First192Bits(ClientRandom) + First192Bits(ServerRandom)
    preMasterSecret = client_random[0..23] + server_random[0..23]

    # PreMasterHash(I) = SaltedHash(preMasterSecret, I)
    # MasterSecret = PreMasterHash(0x41) + PreMasterHash(0x4242) + PreMasterHash(0x434343)
    masterSecret = rdp_salted_hash(preMasterSecret, "A", client_random,server_random) +  rdp_salted_hash(preMasterSecret, "BB", client_random,server_random) + rdp_salted_hash(preMasterSecret, "CCC", client_random, server_random)

    # MasterHash(I) = SaltedHash(MasterSecret, I)
    # SessionKeyBlob = MasterHash(0x58) + MasterHash(0x5959) + MasterHash(0x5A5A5A)
    sessionKeyBlob = rdp_salted_hash(masterSecret, "X", client_random,server_random) +  rdp_salted_hash(masterSecret, "YY", client_random,server_random) + rdp_salted_hash(masterSecret, "ZZZ", client_random, server_random)

    # InitialClientDecryptKey128 = FinalHash(Second128Bits(SessionKeyBlob))
    initialClientDecryptKey128 = rdp_final_hash(sessionKeyBlob[16..31], client_random, server_random)

    # InitialClientEncryptKey128 = FinalHash(Third128Bits(SessionKeyBlob))
    initialClientEncryptKey128 = rdp_final_hash(sessionKeyBlob[32..47], client_random, server_random)

    macKey = sessionKeyBlob[0..15]

    return initialClientEncryptKey128, initialClientDecryptKey128, macKey, sessionKeyBlob
  end

  def rsa_encrypt(bignum, rsexp, rsmod)
    (bignum ** rsexp) % rsmod
  end

  def rdp_rc4_crypt(rc4obj, data)
    rc4obj.encrypt(data)
  end

  def bytes_to_bignum(bytesIn, order = "little")
    bytes = bin_to_hex(bytesIn)
    if order == "little"
      bytes = bytes.scan(/../).reverse.join('')
    end
    s = "0x"+bytes
    s.to_i(16)
  end

  def bignum_to_bytes(bigNum, order = "little")
    int_to_bytestring(bigNum)
    if order == "little"
      bytes = bytes.scan(/../).reverse.join('')
    end
  end

  # https://www.ruby-forum.com/t/integer-to-byte-string-speed-improvements/67110
  def int_to_bytestring( daInt, num_chars = nil )
    unless num_chars
      bits_needed = Math.log( daInt ) / Math.log( 2 )
      num_chars = ( bits_needed / 8.0 ).ceil
    end
    if pack_code = { 1=>'C', 2=>'S', 4=>'L' }[ num_chars ]
      [ daInt ].pack( pack_code )
    else
      a = (0..(num_chars)).map{ |i|
        (( daInt >> i*8 ) & 0xFF ).chr
      }.join
      a[0..-2] # seems legit lol
    end
  end

  def bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
  end

  #
  # Standard RDP
  # Protocol Data Unit definitions
  #

  # Builds x.224 Data (DT) TPDU - Section 13.7
  def build_data_tpdu(data)
    tpkt_length = data.length + 7

    "\x03\x00" +               # TPKT Header version 03, reserved 0
    [tpkt_length].pack("S>") + # TPKT length
    "\x02\xf0\x80" +           # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
    data
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
  # Client X.224 Connect Request PDU - 2.2.1.1
  def pdu_negotiation_request(requested_protocols = 0)
    "\x03\x00" +    # TPKT Header version 03, reserved 0
    "\x00\x2b" +    # TPKT length: 43
    "\x26" +        # X.224 Data TPDU length: 38
    "\xe0" +        # X.224 Type: Connect Request
    "\x00\x00" +    # dst reference
    "\x00\x00" +    # src reference
    "\x00" +        # class and options
    # cookie - literal 'Cookie: mstshash='
    "\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d" +
    Rex::Text.rand_text_alpha(5) + # Identifier "username"
    "\x0d\x0a" +     # cookie terminator
    "\x01\x00" +     # Type: RDP Negotiation Request ( 0x01 )
    "\x08\x00" +     # Length
    [requested_protocols].pack('L<') # requestedProtocols
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b
  def pdu_connect_initial(selected_proto = 0)
    # After negotiating TLS or NLA the connectInitial packet needs to include the
    # protocol selection that the server indicated in its Negotiation Response

    # This needs to be reworked and documented.
    pdu = "\x7f\x65" + # T.125 Connect-Initial (BER: Application 101)
    "\x82\x01\xbe" +   # Length (BER: Length)
    "\x04\x01\x01" +   # CallingDomainSelector: 1 (BER: OctetString)
    "\x04\x01\x01" +   # CalledDomainSelector: 1 (BER: OctetString)
    "\x01\x01\xff" +   # UpwaredFlag: True (BER: boolean)
    # Connect-Initial: Target Parameters
    "\x30\x20" +          # TargetParamenters (BER: SequenceOf)
    # Not sure why the BER encoded Integers below have 2 byte values instead of one.
    "\x02\x02\x00\x22" +  # MaxChannelIds: 34    (BER: Int)
    "\x02\x02\x00\x02" +  # MaxUserIDs: 2        (BER: Int)
    "\x02\x02\x00\x00" +  # MaxTokenIds: 0       (BER: Int)
    "\x02\x02\x00\x01" +  # NumPriorities: 1     (BER: Int)
    "\x02\x02\x00\x00" +  # MinThroughput: 0     (BER: Int)
    "\x02\x02\x00\x01" +  # MaxHeight: 1         (BER: Int)
    "\x02\x02\xff\xff" +  # MaxMCSPDUSize: 65535 (BER: Int)
    "\x02\x02\x00\x02" +  # ProtocolVersion: 2   (BER: Int)
    # Connect-Intial: Minimum Parameters
    "\x30\x20" +          # MinimumParameters (BER: SequencOf)
    "\x02\x02\x00\x01" +  # MaxChannelIds: 1     (BER: Int)
    "\x02\x02\x00\x01" +  # MaxUserIDs: 1        (BER: Int)
    "\x02\x02\x00\x01" +  # MaxTokenIds: 1       (BER: Int)
    "\x02\x02\x00\x01" +  # NumPriorities: 1     (BER: Int)
    "\x02\x02\x00\x00" +  # MinThroughput: 0     (BER: Int)
    "\x02\x02\x00\x01" +  # MaxHeight: 1         (BER: Int)
    "\x02\x02\x04\x20" +  # MaxMCSPDUSize: 1056  (BER: Int)
    "\x02\x02\x00\x02" +  # ProtocolVersion: 2   (BER: Int)
    # Connect-Initial: Maximum Parameters
    "\x30\x20" +          # MaximumParameters (BER: SequencOf)
    "\x02\x02\xff\xff" +  # MaxChannelIds: 65535  (BER: Int)
    "\x02\x02\xfc\x17" +  # MaxUserIDs: 64535     (BER: Int)
    "\x02\x02\xff\xff" +  # MaxTokenIds: 65535    (BER: Int)
    "\x02\x02\x00\x01" +  # NumPriorities: 1      (BER: Int)
    "\x02\x02\x00\x00" +  # MinThroughput: 0      (BER: Int)
    "\x02\x02\x00\x01" +  # MaxHeight: 1          (BER: Int)
    "\x02\x02\xff\xff" +  # MaxMCSPDUSize: 65535  (BER: Int)
    "\x02\x02\x00\x02" +  # ProtocolVersion: 2    (BER: Int)
    # Connect-Initial: UserData
    "\x04\x82\x01\x4b" +  # UserData, length 331  (BER: OctetString)
    # T.124 GCC Connection Data (ConnectData)- PER Encoding used
    "\x00\x05" + # object length
    "\x00\x14\x7c\x00\x01" + # object: OID 0.0.20.124.0.1 = Generic Conference Control
    "\x81\x42" + # Length: 322 (Connect PDU)
    "\x00\x08\x00\x10\x00\x01\xc0\x00" + # T.124 Connect PDU, Conference name 1
    "\x44\x75\x63\x61" + # h221NonStandard: 'Duca' (client-to-server H.221 key)
    "\x81\x34" + # Length: 308 (T.124 UserData section)
    # Client MCS Section - 2.2.1.3
    "\x01\xc0" + # clientCoreData (TS_UD_CS_CORE) header - 2.2.1.3.2
    "\xd8\x00" + # Length: 216 (includes header)
    "\x04\x00\x08\x00" + # version: 8.4 (RDP 5.0 -> 8.1)
    "\x20\x03" + # desktopWidth: 800
    "\x58\x02" + # desktopHeigth: 600
    "\x01\xca" + # colorDepth: 8 bpp
    "\x03\xaa" + # SASSequence: 43523
    "\x09\x04\x00\x00" + # keyboardLayout: 1033 (English US)
    "\x28\x0a\x00\x00" + # clientBuild: 2600
    # clientName: x1810 (15 Unicode chars + null terminator )- FIXME
    "\x78\x00\x31\x00\x38\x00\x31\x00\x30\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x04\x00\x00\x00" + # keyboardType: 4 (IBMEnhanced 101 or 102)
    "\x00\x00\x00\x00" + # keyboadSubtype: 0
    "\x0c\x00\x00\x00" + # keyboardFunctionKey: 12
    # imeFileName (64 bytes)
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x01\xca" + # postBeta2ColorDepth: 8 bpp
    "\x01\x00" + # clientProductID: 1
    "\x00\x00\x00\x00" + # serialNumber: 0
    "\x18\x00" + # highColorDepth: 24 bpp
    "\x07\x00" + # supportedColorDepths: flag (24 bpp | 16 bpp | 15 bpp )
    "\x01\x00" + # earlyCapabilityFlags: 1 (RNS_UD_CS_SUPPORT_ERRINFO_PDU)
    # clientDigProductID (64 bytes)
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00" + # connectionType: 0
    "\x00" + # pad1octet
    # serverSelectedProtocol - After negotiating TLS or CredSSP this value must
    # match the selectedProtocol value from the server's Negotiate Connection
    # confirm PDU that was sent before encryption was started.
    [selected_proto].pack('L<') +
    "\x04\xc0" + # clientClusterdata (TS_UD_CS_CLUSTER) header - 2.2.1.3.5
    "\x0c\x00" + # Length: 12 (includes header)
    "\x09\x00\x00\x00" + # flags (REDIRECTION_SUPPORTED | REDIRECTION_VERSION3)
    "\x00\x00\x00\x00" + # RedirectedSessionID
    "\x02\xc0" + # clientSecuritydata (TS_UD_CS_SEC) header - 2.2.1.3.3
    "\x0c\x00" + # Length: 12 (includes header)
    "\x03\x00\x00\x00" + # encryptionMethods: 3 (40 bit | 128 bit)
    "\x00\x00\x00\x00" + # extEncryptionMethods (French locale only)
    "\x03\xc0" + # clientNetworkData (TS_UD_CS_NET) - 2.2.1.3.4
    "\x44\x00" + # Length: 68 (includes header)
    "\x05\x00\x00\x00" + # channelCount: 5
    # Channels definitions consist of a name (8 bytes) and options flags
    # (4 bytes). Names are up to 7 ANSI characters with null termination.
    "\x63\x6c\x69\x70\x72\x64\x72\x00" + # 'cliprdr'
    "\xc0\xa0\x00\x00" +
    "\x4d\x53\x5f\x54\x31\x32\x30\x00" + # 'MS_T120'
    "\x80\x80\x00\x00" +
    "\x72\x64\x70\x73\x6e\x64\x00\x00" + # 'rdpsnd
    "\xc0\x00\x00\x00" +
    "\x73\x6e\x64\x64\x62\x67\x00\x00" + # 'snddbg'
    "\xc0\x00\x00\x00" +
    "\x72\x64\x70\x64\x72\x00\x00\x00" + # 'rdpdr'
    "\x80\x80\x00\x00"

    build_data_tpdu(pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c
  # Client MCS Erect Domain Request PDU - 2.2.1.5
  def pdu_erect_domain_request
    pdu = "\x04" + # T.125 ErectDomainRequest
    "\x01\x00" +   # subHeight - length 1, value 0
    "\x01\x00"     # subInterval - length 1, value 0

    build_data_tpdu(pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247\
  # Client MCS Attach User Request PDU - 2.2.1.6
  def pdu_attach_user_request
    pdu = "\x28"  # T.125 AttachUserRequest

    build_data_tpdu(pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b
  # Client MCS Channel Join Request PDU -2.2.1.8
  def pdu_channel_request(user1, channel_id)
    pdu = "\x38" +                  # T.125 ChannelJoinRequest
    [user1, channel_id].pack("nn")

    build_data_tpdu(pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-ac8b-704db419b66f
  # Client Security Exchange PDU - 2.2.1.10
  def pdu_security_exchange(rcran, rsexp, rsmod, bitlen)
    encrypted_rcran_bignum = rsa_encrypt(rcran, rsexp, rsmod)
    encrypted_rcran = int_to_bytestring(encrypted_rcran_bignum)

    bitlen += 8 # Pad with size of TS_SECURITY_PACKET header

    userdata_length = 8 + bitlen
    userdata_length_low = userdata_length & 0xFF
    userdata_length_high = userdata_length / 256
    flags = 0x80 | userdata_length_high

    pdu = "\x64" +      # T.125 sendDataRequest
    "\x00\x08" +        # intiator userId
    "\x03\xeb" +        # channelId = 1003
    "\x70" +            # dataPriority = high, segmentation = begin | end
    [flags].pack("C") +
    [userdata_length_low].pack("C") + # UserData length
    # TS_SECURITY_PACKET - 2.2.1.10.1
    "\x01\x00" +           # securityHeader flags
    "\x00\x00" +           # securityHeader flagsHi
    [bitlen].pack("L<") +  # TS_ length
    encrypted_rcran +      # encryptedClientRandom - 64 bytes
    "\x00\x00\x00\x00\x00\x00\x00\x00" # 8 bytes rear padding (always present)

    build_data_tpdu(pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/772d618e-b7d6-4cd0-b735-fa08af558f9d
  # TS_INFO_PACKET - 2.2.1.11.1.1
  def pdu_client_info
    "\x00\x00\x00\x00" +  # CodePage
    "\x33\x01\x00\x00" +  # flags - INFO_MOUSE, INFO_DISABLECTRLALTDEL, INFO_UNICODE, INFO_MAXIMIZESHELL, INFO_ENABLEWINDOWSKEY
    "\x00\x00" +  # cbDomain (length value)
    "\x0a\x00" +  # cbUserName (length value): 10 EXCLUDES null terminator
    "\x00\x00" +  # cbPassword (length value)
    "\x00\x00" +  # cbAlternateShell (length value)
    "\x00\x00" +  # cbWorkingDir (length value)
    "\x00\x00" +  # Domain - empty
    "\x75\x00\x73\x00\x65\x00\x72\x00\x30\x00" + # UserName: user0 - FIXME use global name value, set cbUsername above as well
    "\x00\x00" +  # UserName null terminator, EXCLUDED FROM value of cbUserName
    "\x00\x00" +  # Password - empty
    "\x00\x00" +  # AlternateShell - empty
    "\x00\x00" +  # WorkingDir - empty
    # TS_EXTENDED_INFO_PACKET - 2.2.1.11.1.1.1
    "\x02\x00" +  # clientAddressFamily - AF_INET
    "\x1c\x00" +  # cbClientAddress (length value): 28
    # clientAddress: 192.168.1.208 - FIXME
    "\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x38\x00\x2e\x00\x31\x00\x2e\x00\x32\x00\x30\x00\x38\x00" +
    "\x00\x00" +  # clientAddress null terminator, included in value of cbClientAddress
    "\x3c\x00" +  # cbClientDir (length value): 60
    # clientDir - 'C:\WINNT\System32\mstscax.dll' + null terminator
    "\x3c\x00\x43\x00\x3a\x00\x5c\x00\x57\x00\x49\x00\x4e\x00\x4e\x00" +
    "\x54\x00\x5c\x00\x53\x00\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00" +
    "\x33\x00\x32\x00\x5c\x00\x6d\x00\x73\x00\x74\x00\x73\x00\x63\x00" +
    "\x61\x00\x78\x00\x2e\x00\x64\x00\x6c\x00\x6c\x00\x00\x00" +
    # clientTimeZone - TS_TIME_ZONE struct - 172 bytes
    "\xa4\x01\x00\x00" + # Bias
    # StandardName - 'GTB,normaltid'
    "\x47\x00\x54\x00\x42\x00\x2c\x00\x20\x00\x6e\x00\x6f\x00\x72\x00" +
    "\x6d\x00\x61\x00\x6c\x00\x74\x00\x69\x00\x64\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x0a\x00\x00\x00\x05\x00\x03\x00\x00\x00\x00\x00\x00\x00" + # StandardDate - Oct 5
    "\x00\x00\x00\x00" + # StandardBias
    # DaylightName - 'GTB,sommartid'
    "\x47\x00\x54\x00\x42\x00\x2c\x00\x20\x00\x73\x00\x6f\x00\x6d\x00" +
    "\x6d\x00\x61\x00\x72\x00\x74\x00\x69\x00\x64\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
    "\x00\x00\x03\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00\x00\x00" + # DaylightDate - Mar 3
    "\xc4\xff\xff\xff" + # DaylightBias
    "\x00\x00\x00\x00" + # clientSessionId
    "\x27\x00\x00\x00" + # performanceFlags
    "\x00\x00"           # cbAutoReconnectCookie
  end

  # Build share headers
  # 2.2.8.1.1.1
  def build_share_headers(type, data)

    uncompressed_len = data.length + 4
    total_len = uncompressed_len + 14

    [total_len].pack("S<") + # totalLength - includes all headers
    "\x17\x00" + # pduType = flags TS_PROTOCOL_VERSION | PDUTYPE_DATAPDU
    "\xf1\x03" + # PDUSource: 0x03f1 = 1009
    "\xea\x03\x01\x00" + # shareId: 66538
    "\x00" +     # pad1
    "\x01" +     # streamID: 1
    [uncompressed_len].pack("S<") + # uncompressedLength - 16 bit, unsigned int
    type +       # pduType2 - 8 bit, unsighted int - 2.2.8.1.1.2
    "\x00" +     # compressedType: 0
    "\x00\x00" + # compressedLength: 0
    data
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9d1e1e21-d8b4-4bfd-9caf-4b72ee91a7135
  # Control Cooperate - TC_CONTROL_PDU 2.2.1.15
  def pdu_client_control_cooperate
    pdu = "\x04\x00" + # action: 4 - CTRLACTION_COOPERATE
    "\x00\x00" +       # grantId: 0
    "\x00\x00\x00\x00" # controlId: 0

    # pduType2 = 0x14 = 20 - PDUTYPE2_CONTROL
    build_share_headers("\x14", pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4f94e123-970b-4242-8cf6-39820d8e3d35
  # Control Request - TC_CONTROL_PDU 2.2.1.16
  def pdu_client_control_request
    pdu = "\x01\x00" + # action: 1 - CTRLACTION_REQUEST_CONTROL
    "\x00\x00" +       # grantId: 0
    "\x00\x00\x00\x00" # controlId: 0

    # pduType2 = 0x14 = 20 - PDUTYPE2_CONTROL
    build_share_headers("\x14", pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7067da0d-e318-4464-88e8-b11509cf0bd9
  # Client Font List - TS_FONT_LIST_PDU - 2.2.1.18
  def pdu_client_font_list
    pdu = "\x00\x00" + # numberFonts: 0
    "\x00\x00" + # totalNumberFonts: 0
    "\x03\x00" + # listFlags: 3 (FONTLIST_FIRST | FONTLIST_LAST)
    "\x32\x00"   # entrySize: 50

    # pduType2 = 0x27 = 39 - PDUTYPE2_FONTLIST
    build_share_headers("\x27", pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5186005a-36f5-4f5d-8c06-968f28e2d992
  # Client Synchronize - TS_SYNCHRONIZE_PDU - 2.2.1.19 /  2.2.14.1
  def pdu_client_synchronize(target_user = 0)
    pdu = "\x01\x00" +        # messageType: 1 SYNCMSGTYPE_SYNC
    [target_user].pack("S<")  # targetUser, 16 bit, unsigned.

    # pduType2 = 0x1f = 31 - PDUTYPE2_SCYNCHRONIZE
    build_share_headers("\x1f", pdu)
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4c3c2710-0bf0-4c54-8e69-aff40ffcde66
  def pdu_client_confirm_active
    data = "a4011300f103ea030100ea0306008e014d53545343000e00000001001800010003000002000000000d04000000000000000002001c00100001000100010020035802000001000100000001000000030058000000000000000000000000000000000000000000010014000000010047012a000101010100000000010101010001010000000000010101000001010100000000a1060000000000000084030000000000e40400001300280000000003780000007800000050010000000000000000000000000000000000000000000008000a000100140014000a0008000600000007000c00000000000000000005000c00000000000200020009000800000000000f000800010000000d005800010000000904000004000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe000001400000080001000102000000"

    [data].pack("H*")
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2d122191-af10-4e36-a781-381e91c182b7
  def pdu_client_persistent_key_list
    data = "49031700f103ea03010000013b031c00000001000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    [data].pack("H*")
  end

end
