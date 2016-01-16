##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/login_scanner/redis'
require 'metasploit/framework/credential_collection'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Redis
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'         => 'Redis Login Utility',
        'Description'  => 'This module attempts to authenticate to an REDIS service.',
        'Author'       => [ 'Nixawk' ],
        'References'   => [
          ['URL', 'http://redis.io/topics/protocol']
        ],
        'License'      => MSF_LICENSE))

    register_options(
      [
        OptPath.new('PASS_FILE',
          [
            false,
            'The file that contains a list of of probable passwords.',
            File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_passwords.txt')
          ])
      ], self.class)

    # redis does not have an username, there's only password
    deregister_options('USERNAME', 'USER_AS_PASS', 'USERPASS_FILE', 'USER_FILE', 'DB_ALL_USERS')
  end

  def run_host(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      # The LoginScanner API refuses to run if there's no username, so we give it a fake one.
      # But we will not be reporting this to the database.
      username: 'redis'
    )

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::REDIS.new(
      host: ip,
      port: rport,
      ssl: datastore['SSL'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      max_send_size: datastore['TCP::max_send_size'],
      send_delay: datastore['TCP::send_delay'],
      framework: framework,
      framework_module: self,
      ssl_version: datastore['SSLVersion'],
      ssl_verify_mode: datastore['SSLVerifyMode'],
      ssl_cipher: datastore['SSLCipher'],
      local_port: datastore['CPORT'],
      local_host: datastore['CHOST']
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

        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end
end
