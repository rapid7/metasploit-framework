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

    register_options(
      [
        OptBool.new(
          'APPEND_DOMAIN', [true, 'Appends `@<DOMAIN> to the username for authentication`', false],
          conditions: ['LDAP::Auth', 'in', [Msf::Exploit::Remote::AuthOption::AUTO, Msf::Exploit::Remote::AuthOption::PLAINTEXT]]
        )
      ]
    )

    # A password must be supplied unless doing anonymous login
    deregister_options('BLANK_PASSWORDS')
  end

  def run
    validate_connect_options!
    super
  end

  def validate_connect_options!
    # Verify we can create arbitrary connect opts, this won't make a connection out to the real host - but will verify the values are valid
    get_connect_opts
  rescue Msf::ValidationError => e
    fail_with(Msf::Exploit::Remote::Failure::BadConfig, "Invalid datastore options for chosen auth type: #{e.message}")
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
      realm: datastore['DOMAIN'],
      anonymous_login: datastore['ANONYMOUS_LOGIN'],
      blank_passwords: false
    )

    opts = {
      domain: datastore['DOMAIN'],
      append_domain: datastore['APPEND_DOMAIN'],
      ssl: datastore['SSL'],
      proxies: datastore['PROXIES'],
      domain_controller_rhost: datastore['DomainControllerRhost'],
      ldap_auth: datastore['LDAP::Auth'],
      ldap_cert_file: datastore['LDAP::CertFile'],
      ldap_rhostname: datastore['Ldap::Rhostname'],
      ldap_krb_offered_enc_types: datastore['Ldap::KrbOfferedEncryptionTypes'],
      ldap_krb5_cname: datastore['Ldap::Krb5Ccname'],
      # Write only cache so we keep all gathered tickets but don't reuse them for auth while running the module
      kerberos_ticket_storage: kerberos_ticket_storage({ read: false, write: true })
    }

    realm_key = nil
    if opts[:ldap_auth] == Msf::Exploit::Remote::AuthOption::KERBEROS
      realm_key = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
    end

    scanner = Metasploit::Framework::LoginScanner::LDAP.new(
      host: ip,
      port: rport,
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: datastore['LDAP::ConnectTimeout'].to_i,
      framework: framework,
      framework_module: self,
      realm_key: realm_key,
      opts: opts
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        service_name: 'ldap',
        protocol: 'tcp'
      )
      if result.success?
        if opts[:ldap_auth] == Msf::Exploit::Remote::AuthOption::SCHANNEL
          # Schannel auth has no meaningful credential information to store in the DB
          print_brute level: :good, ip: ip, msg: "Success: 'Cert File #{opts[:ldap_cert_file]}'"
        else
          create_credential_and_login(credential_data)
          print_brute level: :good, ip: ip, msg: "Success: '#{result.credential}'"
        end
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end
end
