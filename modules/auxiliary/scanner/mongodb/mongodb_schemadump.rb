##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'
require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MongoDB Schema Enumerator',
        'Description' => %q{
          This module connects to an unauthenticated or authenticated MongoDB instance,
          authenticates using SCRAM-SHA-1 if credentials are provided, enumerates
          databases and collections via wire protocol, samples documents, and dumps
          the inferred schema structure.

          Sccuessfully tested against MongoDB 3.6 with and without authentication
        },
        'Author' => [ 'h00die' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/' ]
        ],
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
        OptString.new('DB_NAME', [ false, 'Specific database to enumerate (leave blank for all)', '' ]),
        OptString.new('AUTH_DB', [ false, 'Database to authenticate against', 'admin' ]),
        OptString.new('USERNAME', [ false, 'Username for authentication', '' ]),
        OptString.new('PASSWORD', [ false, 'Password for authentication', '' ]),
        OptInt.new('SAMPLE_SIZE', [ true, 'Number of sample documents to inspect per collection for schema mapping', 5 ])
      ]
    )
  end

  def run_host(_ip)
    connect

    print_status('Connected to MongoDB wire protocol')

    if datastore['USERNAME'].present?
      auth_db = datastore['AUTH_DB'].presence || 'admin'
      unless authenticate(auth_db)
        print_error('Stopping scan due to authentication failure.')
        return
      end
    end

    dbs = fetch_databases
    if dbs.empty?
      print_error('Could not retrieve databases.')
      return
    end

    print_good("Found Databases: #{dbs.join(', ')}")

    schema_report = {}

    dbs.each do |db|
      next if datastore['DB_NAME'].present? && datastore['DB_NAME'] != db

      collections = fetch_collections(db)
      print_status("  DB '#{db}' Collections: #{collections.join(', ')}")

      schema_report[db] = {}

      collections.each do |coll|
        fields = sample_collection_schema(db, coll)
        schema_report[db][coll] = fields

        if fields.any?
          vprint_good("    Schema for #{db}.#{coll}:")
          fields.each { |field, type| vprint_line("    - #{field} (#{type})") }
        else
          vprint_status("    Collection #{db}.#{coll} is empty or returned no fields.")
        end
      end
    end

    report_json = JSON.pretty_generate(schema_report)
    loot_path = store_loot(
      'mongodb.schema',
      'application/json',
      rhost,
      report_json,
      'mongodb_schema.json',
      'MongoDB Schema Structure'
    )
    print_good("Schema dumped to loot: #{loot_path}")
  rescue ::Rex::ConnectionError => e
    print_error("Connection failed: #{e.message}")
  ensure
    disconnect
  end

  private

  def authenticate(db = 'admin')
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']

    digest_pass = Digest::MD5.hexdigest("#{user}:mongo:#{pass}")

    client_nonce = Rex::Text.rand_text_alphanumeric(24)
    auth_payload = "n=#{user},r=#{client_nonce}"
    client_first_bare = auth_payload
    client_first_message = "n,,#{auth_payload}"

    sasl_start_cmd = BSON::Document.new({
      'saslStart' => BSON::Int32.new(1),
      'mechanism' => 'SCRAM-SHA-1',
      'payload' => BSON::Binary.new(client_first_message)
    })

    reply = send_query_single("#{db}.$cmd", sasl_start_cmd.to_bson.to_s)
    unless reply && reply['ok'].to_i == 1
      print_error('SCRAM-SHA-1 auth initial request rejected.')
      return false
    end

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

    OpenSSL::HMAC.digest('sha1', salted_password, 'Server Key') # Verification
    client_proof = Rex::Text.xor(client_key, OpenSSL::HMAC.digest('sha1', stored_key, auth_message))
    client_final_message = "#{client_final_without_proof},p=#{Rex::Text.encode_base64(client_proof)}"

    conv_id_bson = conversation_id.is_a?(Integer) ? BSON::Int32.new(conversation_id) : conversation_id

    sasl_continue_cmd = BSON::Document.new({
      'saslContinue' => BSON::Int32.new(1),
      'conversationId' => conv_id_bson,
      'payload' => BSON::Binary.new(client_final_message)
    })

    reply = send_query_single("#{db}.$cmd", sasl_continue_cmd.to_bson.to_s)
    unless reply && reply['ok'].to_i == 1
      vprint_error("saslContinue failure: #{reply.inspect}")
      print_error("Authentication failed for '#{user}' on '#{db}'")
      return false
    end

    # Handle final SASL step if done is false or server signature validation is pending
    if reply['done'] == false
      final_cmd = BSON::Document.new({
        'saslContinue' => BSON::Int32.new(1),
        'conversationId' => conv_id_bson,
        'payload' => BSON::Binary.new('')
      })
      reply = send_query_single("#{db}.$cmd", final_cmd.to_bson.to_s)
    end

    if reply && reply['ok'].to_i == 1
      print_good("Authenticated successfully as '#{user}' on '#{db}'")
      true
    else
      print_error('Final SASL confirmation failed.')
      false
    end
  end

  def parse_scram_payload(payload)
    payload.split(',').each_with_object({}) do |var, hash|
      k, v = var.split('=', 2)
      hash[k] = v if k && v
    end
  end

  def fetch_databases
    cmd = BSON::Document.new({
      'listDatabases' => BSON::Int32.new(1)
    })

    reply = send_query_single('admin.$cmd', cmd.to_bson.to_s)
    vprint_status("Post-auth listDatabases reply: #{reply.inspect}")

    return [] unless reply && reply['ok'].to_i == 1 && reply['databases']

    reply['databases'].map { |d| d['name'] }
  end

  def fetch_collections(db)
    # Construct listCollections as a dynamic BSON Document
    cmd = BSON::Document.new({
      'listCollections' => BSON::Int32.new(1)
    })

    reply = send_query_single("#{db}.$cmd", cmd.to_bson.to_s)
    return [] unless reply

    cursor = reply['cursor']
    return [] unless cursor && cursor['firstBatch']

    cursor['firstBatch'].map { |c| c['name'] }
  end

  def sample_collection_schema(db, collection)
    empty_query = "\x05\x00\x00\x00\x00"
    sample_limit = datastore['SAMPLE_SIZE']

    docs = send_query_multi("#{db}.#{collection}", empty_query, sample_limit)
    return {} if docs.empty?

    field_map = {}
    docs.each do |doc|
      extract_fields(doc, '', field_map)
    end

    field_map
  end

  def extract_fields(hash_or_doc, prefix, map)
    hash_or_doc.each do |key, val|
      full_key = prefix.empty? ? key.to_s : "#{prefix}.#{key}"
      map[full_key] ||= val.class.to_s.demodulize

      if val.is_a?(Hash) || val.is_a?(BSON::Document)
        extract_fields(val, full_key, map)
      end
    end
  end

  def send_query_single(full_coll_name, bson_payload)
    docs = send_query_multi(full_coll_name, bson_payload, 1)
    docs.first
  end

  def send_query_multi(full_coll_name, bson_payload, number_to_return = 5)
    coll_name = "#{full_coll_name}\x00"
    req_id = Rex::Text.rand_text(4)

    msg_len = 16 + 4 + coll_name.length + 4 + 4 + bson_payload.length

    packet = [msg_len].pack('V')
    packet << req_id
    packet << "\x00\x00\x00\x00"                  # responseTo
    packet << "\xd4\x07\x00\x00"                  # opCode: 2004 (OP_QUERY)
    packet << "\x00\x00\x00\x00"                  # flags
    packet << coll_name
    packet << "\x00\x00\x00\x00"                  # numberToSkip: 0
    packet << [number_to_return].pack('V')
    packet << bson_payload

    sock.put(packet)
    response_raw = sock.get_once(-1, 5)

    return [] unless response_raw && response_raw.length > 36

    bson_bytes = response_raw[36..]
    docs = []
    offset = 0

    while offset < bson_bytes.length
      break if offset + 4 > bson_bytes.length

      doc_len = bson_bytes[offset..offset + 3].unpack1('V')
      break if doc_len.nil? || doc_len <= 0 || (offset + doc_len) > bson_bytes.length

      buffer = BSON::ByteBuffer.new(bson_bytes[offset...offset + doc_len])
      docs << BSON::Document.from_bson(buffer)
      offset += doc_len
    end

    docs
  rescue StandardError => e
    vprint_error("BSON parsing error: #{e.message}")
    []
  end
end
