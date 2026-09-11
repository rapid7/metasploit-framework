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

          Successfully tested against MongoDB 3.6 with and without authentication
        },
        'Author' => [
          'h00die',
          'prithvee07'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/' ]
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('DB_NAME', [ false, 'Specific database to enumerate (leave blank for all)', '' ]),
        OptInt.new('SAMPLE_SIZE', [ true, 'Number of sample documents to inspect per collection for schema mapping', 5 ])
      ]
    )
  end

  def run_host(_ip)
    connect

    print_status('Connected to MongoDB wire protocol')

    if datastore['USERNAME'].present?
      auth_db = datastore['AUTH_DB'].presence || 'admin'
      mechanism = authenticate(db: auth_db)
      if mechanism
        print_good("Authenticated as '#{datastore['USERNAME']}' on '#{auth_db}' via #{mechanism}")
      else
        print_error('Stopping scan due to authentication failure.')
        return
      end
    end

    dbs = fetch_databases
    if dbs.empty?
      if datastore['DB_NAME'].blank?
        print_error('Could not retrieve databases.')
        return
      end

      # listDatabases is a cluster-level command: a database-scoped user
      # (e.g. readWrite on a single database) is denied it even though it
      # may read that database's collections. With DB_NAME set, skip
      # discovery and enumerate that database directly.
      print_status('Could not list databases (insufficient privileges?); enumerating DB_NAME directly')
      dbs = [datastore['DB_NAME']]
    else
      print_good("Found Databases: #{dbs.join(', ')}")
    end

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

  def fetch_databases
    cmd = BSON::Document.new({
      'listDatabases' => BSON::Int32.new(1)
    })

    reply = send_query_single('admin.$cmd', cmd.to_bson.to_s)
    vprint_status("Post-auth listDatabases reply: #{reply.inspect}")

    if reply && mongodb_query_error([reply])
      return []
    end

    return [] unless reply && reply['ok'].to_i == 1 && reply['databases']

    reply['databases'].map { |d| d['name'] }
  end

  def fetch_collections(db)
    # Construct listCollections as a dynamic BSON Document
    cmd = BSON::Document.new({
      'listCollections' => BSON::Int32.new(1)
    })

    # listCollections returns a command cursor whose firstBatch holds at
    # most the server's batch size; mongodb_query_all follows it with getMore
    # so databases with more collections than the first batch are fully
    # enumerated.
    docs = mongodb_query_all(sock, "#{db}.$cmd", cmd.to_bson.to_s)

    if (error = mongodb_query_error(docs))
      print_error("listCollections on #{db} failed: #{error}")
      return []
    end

    docs.map { |c| c['name'] }.compact
  end

  def sample_collection_schema(db, collection)
    empty_query = "\x05\x00\x00\x00\x00"
    sample_limit = datastore['SAMPLE_SIZE']

    docs = send_query_multi("#{db}.#{collection}", empty_query, sample_limit)
    return {} if docs.empty?

    # A failed collection query comes back as an error document; without this
    # check its fields ($err, code, ok) would pollute the inferred schema.
    if (error = mongodb_query_error(docs))
      vprint_error("Query on #{db}.#{collection} failed: #{error}")
      return {}
    end

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
    send_query_multi(full_coll_name, bson_payload, 1).first
  end

  def send_query_multi(full_coll_name, bson_payload, number_to_return = 5)
    pkt = mongodb_build_packet(full_coll_name, bson_payload, number_to_return: number_to_return)

    sock.put(pkt)
    response_raw = mongodb_read_message(sock, 5)

    mongodb_parse_docs(response_raw)
  end
end
