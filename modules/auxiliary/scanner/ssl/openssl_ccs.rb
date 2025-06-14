##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
  CCS_RECORD_TYPE       = 0x14
  ALERT_RECORD_TYPE     = 0x15
  TLS_VERSION = {
    'SSLv3' => 0x0300,
    '1.0'   => 0x0301,
    '1.1'   => 0x0302,
    '1.2'   => 0x0303
  }

  def initialize
    super(
      'Name'           => 'OpenSSL Server-Side ChangeCipherSpec Injection Scanner',
      'Description'    => %q{
        This module checks for the OpenSSL ChangeCipherSpec (CCS)
        Injection vulnerability. The problem exists in the handling of early
        CCS messages during session negotiation. Vulnerable installations of OpenSSL accepts
        them, while later implementations do not. If successful, an attacker can leverage this
        vulnerability to perform a man-in-the-middle (MITM) attack by downgrading the cipher spec
        between a client and server. This issue was first reported in early June, 2014.
      },
      'Author'         => [
        'Masashi Kikuchi', # Vulnerability discovery
        'Craig Young <CYoung[at]tripwire.com>', # Original Scanner. This module is based on it.
        'juan vazquez' # Metasploit module
      ],
      'References'     =>
        [
          ['CVE', '2014-0224'],
          ['URL', 'http://ccsinjection.lepidum.co.jp/'],
          ['URL', 'http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html'],
          ['URL', 'http://www.tripwire.com/state-of-security/incident-detection/detection-script-for-cve-2014-0224-openssl-cipher-change-spec-injection/'],
          ['URL', 'https://www.imperialviolet.org/2014/06/05/earlyccs.html']
        ],
      'DisclosureDate' => 'Jun 5 2014',
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(443),
        OptEnum.new('TLS_VERSION', [true, 'TLS/SSL version to use', '1.0', ['SSLv3','1.0', '1.1', '1.2']]),
        OptInt.new('RESPONSE_TIMEOUT', [true, 'Number of seconds to wait for a server response', 10])
      ])
  end

  def response_timeout
    datastore['RESPONSE_TIMEOUT']
  end

  def run_host(ip)
    ccs_injection
  end

  def ccs_injection
    connect_result = establish_connect
    return if connect_result.nil?

    vprint_status("Sending CCS...")
    sock.put(ccs)
    alert = sock.get_once(-1, response_timeout)
    if alert.blank?
      print_good("No alert after invalid CCS message, probably vulnerable")
      report
    elsif alert.unpack("C").first == ALERT_RECORD_TYPE
      vprint_error("Alert record as response to the invalid CCS Message, probably not vulnerable")
    elsif alert
      vprint_warning("Unexpected response.")
    end
  end

  def report
    report_vuln({
      :host => rhost,
      :port => rport,
      :name => self.name,
      :refs => self.references,
      :info => "Module #{self.fullname} successfully detected CCS injection"
    })
  end

  def ccs
    payload = "\x01" # Change Cipher Spec Message

    ssl_record(CCS_RECORD_TYPE, payload)
  end

  def client_hello
    # Use current day for TLS time
    time_temp = Time.now
    time_epoch = Time.mktime(time_temp.year, time_temp.month, time_temp.day, 0, 0).to_i

    hello_data = [TLS_VERSION[datastore['TLS_VERSION']]].pack("n") # Version TLS
    hello_data << [time_epoch].pack("N")    # Time in epoch format
    hello_data << Rex::Text.rand_text(28)   # Random
    hello_data << "\x00"                    # Session ID length
    hello_data << [CIPHER_SUITES.length * 2].pack("n") # Cipher Suites length (102)
    hello_data << CIPHER_SUITES.pack("n*")  # Cipher Suites
    hello_data << "\x01"                    # Compression methods length (1)
    hello_data << "\x00"                    # Compression methods: null

    data = "\x01\x00"                      # Handshake Type: Client Hello (1)
    data << [hello_data.length].pack("n")  # Length
    data << hello_data

    ssl_record(HANDSHAKE_RECORD_TYPE, data)
  end

  def ssl_record(type, data)
    record = [type, TLS_VERSION[datastore['TLS_VERSION']], data.length].pack('Cnn')
    record << data
  end

  def establish_connect
    connect

    vprint_status("Sending Client Hello...")
    sock.put(client_hello)
    server_hello = sock.get_once(-1, response_timeout)

    unless server_hello
      vprint_error("No Server Hello after #{response_timeout} seconds...")
      disconnect
      return nil
    end

    unless server_hello.unpack("C").first == HANDSHAKE_RECORD_TYPE
      vprint_error("Server Hello Not Found")
      return nil
    end

    true
  end
end

