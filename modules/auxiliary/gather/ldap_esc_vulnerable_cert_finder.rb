require 'winrm'
class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::LDAP
  include Msf::Exploit::Remote::LDAP::ActiveDirectory
  include Msf::OptionalSession::LDAP
  include Rex::Proto::MsDnsp
  include Rex::Proto::Secauthz
  include Rex::Proto::LDAP
  include Rex::Proto::CryptoAsn1
  include Rex::Proto::MsCrtd

  class LdapWhoamiError < StandardError; end

  ADS_GROUP_TYPE_BUILTIN_LOCAL_GROUP = 0x00000001
  ADS_GROUP_TYPE_GLOBAL_GROUP = 0x00000002
  ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP = 0x00000004
  ADS_GROUP_TYPE_SECURITY_ENABLED = 0x80000000
  ADS_GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008

  # https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting
  EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

  REFERENCES = {
    'ESC1' => [ SiteReference.new('URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2') ],
    'ESC2' => [ SiteReference.new('URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2') ],
    'ESC3' => [ SiteReference.new('URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2') ],
    'ESC4' => [ SiteReference.new('URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2') ],
    'ESC9' => [ SiteReference.new('URL', 'https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7') ],
    'ESC10' => [ SiteReference.new('URL', 'https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7') ],
    'ESC13' => [ SiteReference.new('URL', 'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53') ],
    'ESC15' => [ SiteReference.new('URL', 'https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc') ],
    'ESC16' => [ SiteReference.new('URL', 'https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation') ]
  }.freeze

  SID = Struct.new(:value, :name) do
    def ==(other)
      value == other.value
    end

    def to_s
      name.present? ? "#{value} (#{name})" : value.to_s
    end

    def rid
      value.split('-').last.to_i
    end
  end

  attr_reader :certificate_details

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Misconfigured Certificate Template Finder',
        'Description' => %q{
          This module allows users to query a LDAP server for vulnerable certificate
          templates and will print these certificates out in a table along with which
          attack they are vulnerable to and the SIDs that can be used to enroll in that
          certificate template.

          Additionally the module will also print out a list of known certificate servers
          along with info about which vulnerable certificate templates the certificate server
          allows enrollment in and which SIDs are authorized to use that certificate server to
          perform this enrollment operation.

          Currently the module is capable of checking for certificates that are vulnerable to ESC1, ESC2, ESC3, ESC4,
          ESC13, and ESC15. The module is limited to checking for these techniques due to them being identifiable
          remotely from a normal user account by analyzing the objects in LDAP.

          The module can also check for ESC9, ESC10 and ESC16 but this requires an Administrative WinRM session to be
          established to definitively check for these techniques.
        },
        'Author' => [
          'Grant Willcox', # Original module author
          'Spencer McIntyre', # ESC13 and ESC15 updates
          'jheysel-r7' # ESC4, ESC9 and ESC10 update
        ],
        'References' => (REFERENCES.values.flatten.map { |r| [ r.ctx_id, r.ctx_val ] }.uniq + [
          ['ATT&CK', Mitre::Attack::Technique::T1649_STEAL_OR_FORGE_AUTHENTICATION_CERTIFICATES]
        ]).uniq,
        'DisclosureDate' => '2021-06-17',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [],
          'AKA' => [ 'Certifry', 'Certipy' ]
        }
      )
    )

    register_options([
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptEnum.new('REPORT', [true, 'What templates to report (applies filtering to results)', 'vulnerable-and-published', %w[all published enrollable vulnerable vulnerable-and-published vulnerable-and-enrollable]]),
      OptBool.new('RUN_REGISTRY_CHECKS', [true, 'Authenticate to WinRM to query the registry values to enhance reporting for ESC9, ESC10 and ESC16. Must be a privileged user in order to query successfully', false]),
      OptInt.new('WINRM_TIMEOUT', [false, 'The WinRM timeout when running registry checks', 20], conditions: %w[RUN_REGISTRY_CHECKS == true]),
    ])
  end

  # TODO: Spencer to check all of these are still used and shouldn't be moved
  # Constants Definition
  CERTIFICATE_ATTRIBUTES = %w[cn name description nTSecurityDescriptor msPKI-Certificate-Policy msPKI-Enrollment-Flag msPKI-RA-Signature msPKI-Template-Schema-Version pkiExtendedKeyUsage msPKI-Certificate-Name-Flag]
  CERTIFICATE_TEMPLATES_BASE = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration'.freeze
  CONTROL_ACCESS = 0x00000100

  # This returns a list of SIDs that have the CERTIFICATE_ENROLLMENT_EXTENDED_RIGHT or CERTIFICATE_AUTOENROLLMENT_EXTENDED_RIGHT for the given ACL
  def enum_acl_aces(acl)
    acl.aces.each do |ace|
      if ace[:body][:access_mask].blank?
        fail_with(Failure::UnexpectedReply, 'Encountered a DACL/SACL object without an access mask! Either data is an unrecognized type or we are reading it wrong!')
      end
      ace_type_name = Rex::Proto::MsDtyp::MsDtypAceType.name(ace[:header][:ace_type])
      if ace_type_name.blank?
        print_error("Skipping unexpected ACE of type #{ace[:header][:ace_type]}. Either the data was read incorrectly or we currently don't support this type.")
        next
      end
      if ace[:header][:ace_flags][:inherit_only_ace] == 1
        # ACE only affects those that inherit from it, not those that it is attached to. Ignoring this ACE, as its not relevant.
        next
      end

      yield ace_type_name, ace
    end
  end

  def get_sids_for_enroll(acl)
    allowed_sids = []
    enum_acl_aces(acl) do |_ace_type_name, ace|
      matcher = SecurityDescriptorMatcher::MultipleAny.new([
        SecurityDescriptorMatcher::Allow.certificate_enrollment,
        SecurityDescriptorMatcher::Allow.certificate_autoenrollment
      ])

      next if matcher.ignore_ace?(ace)

      matcher.apply_ace!(ace)
      next unless matcher.matches?

      allowed_sids << ace[:body][:sid]
    end
    map_sids_to_names(allowed_sids)
  end

  # This will return a list of SIDs that can edit the template from which the ACL is derived
  # The method checks the WriteOwner, WriteDacl and GenericWrite bits of the access_mask to see if the user or group has write permissions over the Certificate
  def get_sids_for_write(acl)
    allowed_sids = []
    enum_acl_aces(acl) do |_ace_type_name, ace|
      matcher = SecurityDescriptorMatcher::Allow.any(%i[WO WD GW])
      next if matcher.ignore_ace?(ace)

      matcher.apply_ace!(ace)
      next unless matcher.matches?

      allowed_sids << ace[:body][:sid]
    end
    map_sids_to_names(allowed_sids)
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

    returned_entries = @ldap.search(base: full_base_dn, filter: filter, attributes: attributes, controls: [adds_build_ldap_sd_control])
    query_result_table = @ldap.get_operation_result.table
    validate_query_result!(query_result_table, filter)
    returned_entries
  end

  def query_ldap_server_certificates(esc_raw_filter, esc_id, notes: [])
    esc_entries = query_ldap_server(esc_raw_filter, CERTIFICATE_ATTRIBUTES, base_prefix: CERTIFICATE_TEMPLATES_BASE)

    if esc_entries.empty?
      print_warning("Couldn't find any vulnerable #{esc_id} templates!")
      return
    end

    # Grab a list of certificates that contain vulnerable settings.
    # Also print out the list of SIDs that can enroll in that server.
    esc_entries.each do |entry|
      certificate_symbol = entry[:cn][0].to_sym
      certificate_details = @certificate_details[certificate_symbol]

      certificate_details[:techniques] << esc_id
      certificate_details[:notes] += notes
    end
  end

  def map_sids_to_names(sids_array)
    mapped = []
    sids_array.each do |sid|
      # these common SIDs don't always have an entry
      case sid
      when Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
        mapped << SID.new(sid, 'Authenticated Users')
        next
      when Rex::Proto::Secauthz::WellKnownSids::SECURITY_ENTERPRISE_CONTROLLERS_SID
        mapped << SID.new(sid, 'Enterprise Domain Controllers')
        next
      when Rex::Proto::Secauthz::WellKnownSids::SECURITY_LOCAL_SYSTEM_SID
        mapped << SID.new(sid, 'Local System')
        next
      end

      sid_entry = get_object_by_sid(sid)
      if sid_entry.nil?
        print_warning("Could not find any details on the LDAP server for SID #{sid}!")
        mapped << SID.new(sid, name)
      elsif sid_entry[:samaccountname].present?
        mapped << SID.new(sid, sid_entry[:samaccountname].first.to_s)
      elsif sid_entry[:name].present?
        mapped << SID.new(sid, sid_entry[:name].first.to_s)
      end
    end

    mapped
  end

  def find_esc1_vuln_cert_templates
    esc1_raw_filter = '(&'\
      '(objectclass=pkicertificatetemplate)'\
      '(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))'\
      '(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))'\
      '(|'\
        '(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)'\
        '(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)'\
        '(pkiextendedkeyusage=1.3.6.1.5.2.3.4)'\
        '(pkiextendedkeyusage=2.5.29.37.0)'\
        '(!(pkiextendedkeyusage=*))'\
      ')'\
      '(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1)'\
    ')'
    notes = [
      'ESC1: Request can specify a subjectAltName (msPKI-Certificate-Name-Flag) and EKUs permit authentication'
    ]
    query_ldap_server_certificates(esc1_raw_filter, 'ESC1', notes: notes)
  end

  def find_esc2_vuln_cert_templates
    esc2_raw_filter = '(&'\
      '(objectclass=pkicertificatetemplate)'\
      '(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))'\
      '(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))'\
      '(|'\
        '(pkiextendedkeyusage=2.5.29.37.0)'\
        '(!(pkiextendedkeyusage=*))'\
      ')'\
    ')'
    notes = [
      'ESC2: Template defines the Any Purpose OID or no EKUs (PkiExtendedKeyUsage)'
    ]
    query_ldap_server_certificates(esc2_raw_filter, 'ESC2', notes: notes)
  end

  def find_esc3_vuln_cert_templates
    # Find the first vulnerable types of ESC3 templates, those that have the OID of the
    # Certificate Request Agent which allows the template to be used for
    # requesting other certificate templates on behalf of other principals.
    esc3_template_1_raw_filter = '(&'\
      '(objectclass=pkicertificatetemplate)'\
      '(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))'\
      '(|'\
        '(mspki-ra-signature=0)'\
        '(!(mspki-ra-signature=*))'\
      ')'\
      '(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.1)'\
    ')'
    notes = [
      'ESC3: Template defines the Certificate Request Agent OID (PkiExtendedKeyUsage)'
    ]
    query_ldap_server_certificates(esc3_template_1_raw_filter, 'ESC3', notes: notes)

    # Find the second vulnerable types of ESC3 templates, those that
    # have the right template schema version and, for those with a template
    # version of 2 or greater, have an Application Policy Insurance Requirement
    # requiring the Certificate Request Agent EKU.
    #
    # Additionally, the certificate template must also allow for domain authentication
    # and the CA must not have any enrollment agent restrictions.
    esc3_template_2_raw_filter = '(&'\
      '(objectclass=pkicertificatetemplate)'\
      '(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))'\
      '(|'\
        '(mspki-template-schema-version=1)'\
        '(&'\
          '(mspki-template-schema-version>=2)'\
          '(msPKI-RA-Application-Policies=1.3.6.1.4.1.311.20.2.1)'\
        ')'\
      ')'\
      '(|'\
        '(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)'\
        '(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)'\
        '(pkiextendedkeyusage=1.3.6.1.5.2.3.4)'\
        '(pkiextendedkeyusage=2.5.29.37.0)'\
        '(!(pkiextendedkeyusage=*))'\
      ')'\
    ')'
    query_ldap_server_certificates(esc3_template_2_raw_filter, 'ESC3_TEMPLATE_2')
  end

  def find_esc4_vuln_cert_templates
    esc_raw_filter = '(objectclass=pkicertificatetemplate)'
    attributes = ['cn', 'description', 'ntSecurityDescriptor']
    esc_entries = query_ldap_server(esc_raw_filter, attributes, base_prefix: CERTIFICATE_TEMPLATES_BASE)

    return if esc_entries.empty?

    current_user = adds_get_current_user(@ldap)[:samaccountname].first
    esc_entries.each do |entry|
      certificate_symbol = entry[:cn][0].to_sym
      if adds_obj_grants_permissions?(@ldap, entry, SecurityDescriptorMatcher::Allow.any(%i[WP]))
        @certificate_details[certificate_symbol][:techniques] << 'ESC4'
        @certificate_details[certificate_symbol][:notes] << "ESC4: The account: #{current_user} has edit permissions over the template #{certificate_symbol}."
      end
    end
  end

  def parse_registry_output(output, property_name)
    return nil if output.stderr.present?

    stdout = output.stdout if output.stdout.present?
    return nil unless stdout

    line_with_property = stdout.lines.find { |line| line.strip.match(/^#{Regexp.escape(property_name)}\s*:/) }
    return nil unless line_with_property

    line_with_property.split(':', 2).last&.strip
  end

  def run_registry_command(shell, path, property_name, dynamic_value = nil)
    full_path = dynamic_value ? "#{path}\\#{dynamic_value}" : path
    command = "Get-ItemProperty -Path '#{full_path}' -Name #{property_name}"
    output = shell.run(command)
    value = parse_registry_output(output, property_name)
    if value.nil?
      print_error("Registry property '#{property_name}' not found at path '#{full_path}'.")
    end
    value
  end

  def create_winrm_connection(host, domain, user, timeout)
    endpoint = "http://#{host}:5985/wsman"
    WinRM::Connection.new(
      endpoint: endpoint,
      domain: domain,
      user: user,
      password: datastore['LDAPPassword'],
      transport: :negotiate,
      operation_timeout: timeout
    )
  end

  def query_ca_policy_values(shell)
    active_policy_name = run_registry_command(shell, 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\*\\PolicyModules', 'Active')
    disable_ext = run_registry_command(shell, 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\*\\PolicyModules', 'DisableExtensionList', active_policy_name)
    edit_flags = run_registry_command(shell, 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\*\\PolicyModules', 'EditFlags', active_policy_name).to_i
    { disable_extension_list: disable_ext, edit_flags: edit_flags }
  end

  def query_dc_reg_values(ca_name, ca_ip_address, domain, user)
    conn = create_winrm_connection(datastore['RHOST'], domain, user, datastore['WINRM_TIMEOUT'])
    handled_locally = false
    conn.shell(:powershell) do |shell|
      @registry_values[:certificate_mapping_methods] = run_registry_command(shell, 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel', 'CertificateMappingMethods').to_i
      @registry_values[:strong_certificate_binding_enforcement] = run_registry_command(shell, 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc', 'StrongCertificateBindingEnforcement').to_i
      if datastore['RHOST'] == ca_ip_address
        @registry_values[ca_name.to_sym] = query_ca_policy_values(shell)
        handled_locally = true
      end
      shell.close
    end
    return if handled_locally

    query_ca_reg_values(ca_name, ca_ip_address, domain, user)
  end

  def query_ca_reg_values(ca_name, ca_ip_address, domain, user)
    conn = create_winrm_connection(ca_ip_address, domain, user, datastore['WINRM_TIMEOUT'])
    conn.shell(:powershell) do |shell|
      @registry_values[ca_name.to_sym] = query_ca_policy_values(shell)
      shell.close
    end
  end

  def enum_registry_values
    @registry_values ||= {}
    domain = adds_get_domain_info(@ldap)[:dns_name]
    user = adds_get_current_user(@ldap)[:sAMAccountName].first.to_s
    ca_servers = adds_get_ca_servers(@ldap)
    if ca_servers.empty?
      print_warning('No Certificate Authority servers found in LDAP.')
      return
    end

    ca_servers.each do |ca_server|
      vprint_good("Found CA: #{ca_server[:name]} (#{ca_server[:dNSHostName]})")
      ca_ip_address = Rex::Socket.getaddress(ca_server[:dNSHostName], false)
      unless ca_ip_address
        vprint_error("Unable to resolve the DNS Host Name of the CA server: #{ca_server[:dNSHostName]}. Checking registry values is unable to continue")
        next
      end

      query_dc_reg_values(ca_server[:name], ca_ip_address, domain, user)
    end

    @registry_values
  rescue StandardError => e
    print_error("Failed to query all registry values. Ensure the user has sufficient privileges to query the Domain Controller and Certificate Authorities: #{e.message}.")
    if @registry_values.key?(:certificate_mapping_methods) && @registry_values.key?(:strong_certificate_binding_enforcement)
      print_error('  The user was able to query the Domain Controller but not the Certificate Authorities, meaning the user is likely an Admin but not a Domain Admin. ESC16 reporting will be inaccurate.')
      return @registry_values
    end
  end

  def resolve_group_memberships(user_dn)
    filter = "(member:1.2.840.113556.1.4.1941:=#{ldap_escape_filter(user_dn)})"
    attributes = ['distinguishedName', 'objectSID', 'sAMAccountName']
    groups = query_ldap_server(filter, attributes)

    groups.map do |group|
      {
        dn: group[:distinguishedname].first,
        sid: Rex::Proto::MsDtyp::MsDtypSid.read(group[:objectsid].first).value,
        name: group[:samaccountname].first
      }
    end
  end

  def fetch_group_members(group_dn)
    filter = "(distinguishedName=#{ldap_escape_filter(group_dn)})"
    attributes = ['member'] # Fetch the 'member' attribute which contains the group members

    group_entry = query_ldap_server(filter, attributes)&.first
    return [] unless group_entry && group_entry[:member]

    group_entry[:member]
  end

  def find_users_with_write_and_enroll_rights(enroll_sids)
    users = []
    enroll_sids.each do |sid|
      ldap_object = adds_get_object_by_sid(@ldap, sid.value)
      if ldap_object && ldap_object[:objectclass]&.include?('user')
        if (ldap_object[:ntsecuritydescriptor]) && adds_obj_grants_permissions?(@ldap, ldap_object, SecurityDescriptorMatcher::Allow.any(%i[WP]))
          users << ldap_object[:samaccountname].first
        end
        next
      end

      next unless ldap_object && ldap_object[:objectclass]&.include?('group')

      member_objects = adds_query_group_members(@ldap, ldap_object[:dn].first, object_class: 'user', inherited: true).to_a
      member_objects.each do |member_object|
        next unless member_object[:ntsecuritydescriptor]
        next if users.include?(member_object[:samaccountname].first)

        if adds_obj_grants_permissions?(@ldap, member_object, SecurityDescriptorMatcher::Allow.any(%i[WP]))
          users << member_object[:samaccountname].first
        end
      end
    end

    users&.uniq
  end

  def find_esc9_vuln_cert_templates
    esc9_raw_filter = '(&'\
      '(objectclass=pkicertificatetemplate)'\
      "(mspki-enrollment-flag:1.2.840.113556.1.4.803:=#{CT_FLAG_NO_SECURITY_EXTENSION})"\
      '(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))'\
      '(|'\
        "(pkiextendedkeyusage=#{OIDs::OID_KP_SMARTCARD_LOGON.value})"\
        "(pkiextendedkeyusage=#{OIDs::OID_PKIX_KP_CLIENT_AUTH.value})"\
        "(pkiextendedkeyusage=#{OIDs::OID_ANY_EXTENDED_KEY_USAGE.value})"\
        '(!(pkiextendedkeyusage=*))'\
      ')'\
      '(|'\
        "(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=#{CT_FLAG_SUBJECT_ALT_REQUIRE_UPN})"\
        "(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=#{CT_FLAG_SUBJECT_ALT_REQUIRE_DNS})"\
      ')'\
    ')'

    esc9_templates = query_ldap_server(esc9_raw_filter, CERTIFICATE_ATTRIBUTES + ['msPKI-Certificate-Name-Flag'], base_prefix: CERTIFICATE_TEMPLATES_BASE)
    esc9_templates.each do |template|
      certificate_symbol = template[:cn][0].to_sym

      enroll_sids = @certificate_details[certificate_symbol][:enroll_sids]
      users = find_users_with_write_and_enroll_rights(enroll_sids)
      current_user = adds_get_current_user(@ldap)[:samaccountname].first
      next if users.empty?
      next unless users_compatible_with_template?(current_user, template['mspki-certificate-name-flag'], users)

      user_plural = users.size > 1 ? 'accounts' : 'account'
      has_plural = users.size > 1 ? 'have' : 'has'

      note = "ESC9: The account: #{current_user} has edit permission over the #{user_plural}: #{users.join(', ')} which #{has_plural} enrollment rights for this template."
      if @registry_values[:strong_certificate_binding_enforcement].present?
        note += " Registry value: StrongCertificateBindingEnforcement=#{@registry_values[:strong_certificate_binding_enforcement]}."
      end
      @certificate_details[certificate_symbol][:target_users] = users
      @certificate_details[certificate_symbol][:certificate_name_flags] = template['mspki-certificate-name-flag']
      @certificate_details[certificate_symbol][:techniques] << 'ESC9'
      @certificate_details[certificate_symbol][:notes] << note
    end
  end

  def find_esc10_vuln_cert_templates
    esc10_raw_filter = '(&'\
    '(objectclass=pkicertificatetemplate)'\
    '(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))'\
     '(|'\
        "(pkiextendedkeyusage=#{OIDs::OID_KP_SMARTCARD_LOGON.value})"\
        "(pkiextendedkeyusage=#{OIDs::OID_PKIX_KP_CLIENT_AUTH.value})"\
        "(pkiextendedkeyusage=#{OIDs::OID_ANY_EXTENDED_KEY_USAGE.value})"\
        '(!(pkiextendedkeyusage=*))'\
      ')'\
    '(|'\
      "(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=#{CT_FLAG_SUBJECT_ALT_REQUIRE_UPN})"\
      "(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=#{CT_FLAG_SUBJECT_ALT_REQUIRE_DNS})"\
    ')'\
    ')'

    esc10_templates = query_ldap_server(esc10_raw_filter, CERTIFICATE_ATTRIBUTES + ['msPKI-Certificate-Name-Flag'], base_prefix: CERTIFICATE_TEMPLATES_BASE)
    esc10_templates.each do |template|
      certificate_symbol = template[:cn][0].to_sym

      enroll_sids = @certificate_details[certificate_symbol][:enroll_sids]
      users = find_users_with_write_and_enroll_rights(enroll_sids)
      current_user = adds_get_current_user(@ldap)[:samaccountname].first
      next if users.empty?
      next unless users_compatible_with_template?(current_user, template['mspki-certificate-name-flag'], users)

      user_plural = users.size > 1 ? 'accounts' : 'account'
      has_plural = users.size > 1 ? 'have' : 'has'

      note = "ESC10: The account: #{current_user} has edit permission over the #{user_plural}: #{users.join(', ')} which #{has_plural} enrollment rights for this template."

      if @registry_values[:strong_certificate_binding_enforcement].present? && @registry_values[:certificate_mapping_methods].present?
        note += " Registry values: StrongCertificateBindingEnforcement=#{@registry_values[:strong_certificate_binding_enforcement]}, CertificateMappingMethods=#{@registry_values[:certificate_mapping_methods]}."
      end

      @certificate_details[certificate_symbol][:target_users] = users
      @certificate_details[certificate_symbol][:certificate_name_flags] = template['mspki-certificate-name-flag']
      @certificate_details[certificate_symbol][:techniques] << 'ESC10'
      @certificate_details[certificate_symbol][:notes] << note
    end
  end

  def find_esc13_vuln_cert_templates
    esc_raw_filter = <<~FILTER
      (&
        (objectclass=pkicertificatetemplate)
        (!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))
        (|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))
        (mspki-certificate-policy=*)
      )
    FILTER
    esc_entries = query_ldap_server(esc_raw_filter, CERTIFICATE_ATTRIBUTES, base_prefix: CERTIFICATE_TEMPLATES_BASE)

    if esc_entries.empty?
      print_warning("Couldn't find any vulnerable ESC13 templates!")
      return
    end

    # Grab a list of certificates that contain vulnerable settings.
    # Also print out the list of SIDs that can enroll in that server.
    esc_entries.each do |entry|
      groups = []
      entry['mspki-certificate-policy'].each do |certificate_policy_oid|
        policy = get_pki_object_by_oid(certificate_policy_oid)

        next if policy&.[]('msds-oidtogrouplink').blank?

        # get the group and check it for two conditions
        group = get_group_by_dn(policy['msds-oidtogrouplink'].first)

        # condition 1: the group must be a universal group
        next if (group['grouptype'].first.to_i & ADS_GROUP_TYPE_UNIVERSAL_GROUP) == 0

        # condition 2: the group must have no members (this is enforced in the GUI but check it anyways)
        next if group['member'].present?

        groups << group['samaccountname'].first.to_s
      end
      next if groups.empty?

      certificate_symbol = entry[:cn][0].to_sym
      @certificate_details[certificate_symbol][:techniques] << 'ESC13'
      @certificate_details[certificate_symbol][:notes] << "ESC13 groups: #{groups.join(', ')}"
    end
  end

  def build_authority_details(ldap_object)
    ca_server_fqdn = ldap_object[:dnshostname][0].to_s.downcase
    return unless ca_server_fqdn.present?

    ca_server_ip_address = get_ip_addresses_by_fqdn(ca_server_fqdn)&.first

    if ca_server_ip_address
      report_service({
        host: ca_server_ip_address,
        port: 445,
        proto: 'tcp',
        name: 'AD CS',
        info: "AD CS CA name: #{ldap_object[:name][0]}"
      })

      report_host({
        host: ca_server_ip_address,
        name: ca_server_fqdn
      })
    end

    begin
      security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(ldap_object[:ntsecuritydescriptor][0])
    rescue IOError => e
      fail_with(Failure::UnexpectedReply, "Unable to read security descriptor! Error was: #{e.message}")
    end
    return unless security_descriptor.dacl

    permissions = []
    # The permissions on the CA server are a bit different than those on a template. While the UI also lists "Read", "Issue and Manage Certificates",
    # and "Manage CA", only the "Request Certificates" permissions can be identified by this nTSecurityDescriptor. The certificateAuthority object
    # under CN=Certificate Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local also does not have the extra permissions.
    permissions << 'REQUEST CERTIFICATES' if adds_obj_grants_permissions?(@ldap, ldap_object, SecurityDescriptorMatcher::Allow.certificate_enrollment)

    {
      fqdn: ca_server_fqdn,
      ip_address: ca_server_ip_address,
      enroll_sids: get_sids_for_enroll(security_descriptor.dacl),
      permissions: permissions,
      name: ldap_object[:name][0].to_s,
      dn: ldap_object[:dn][0].to_s
    }
  end

  def build_template_details(ldap_object)
    security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(ldap_object[:ntsecuritydescriptor].first)

    if security_descriptor.dacl
      enroll_sids = get_sids_for_enroll(security_descriptor.dacl)
      write_sids = get_sids_for_write(security_descriptor.dacl)
    else
      enroll_sids = nil
      write_sids = nil
    end

    if adds_obj_grants_permissions?(@ldap, ldap_object, SecurityDescriptorMatcher::Allow.full_control)
      permissions = [ 'FULL CONTROL' ]
    else
      permissions = [ 'READ' ] # if we have the object, we can assume we have read permissions
      permissions << 'WRITE' if adds_obj_grants_permissions?(@ldap, ldap_object, SecurityDescriptorMatcher::Allow.new(:WP))
      permissions << 'ENROLL' if adds_obj_grants_permissions?(@ldap, ldap_object, SecurityDescriptorMatcher::Allow.certificate_enrollment)
      permissions << 'AUTOENROLL' if adds_obj_grants_permissions?(@ldap, ldap_object, SecurityDescriptorMatcher::Allow.certificate_autoenrollment)
    end

    {
      name: ldap_object[:cn][0].to_s,
      techniques: [],
      dn: ldap_object[:dn][0].to_s,
      enroll_sids: enroll_sids,
      write_sids: write_sids,
      security_descriptor: security_descriptor,
      permissions: permissions,
      ekus: ldap_object[:pkiextendedkeyusage].map(&:to_s),
      schema_version: ldap_object[%s(mspki-template-schema-version)].first,
      ca_servers: {},
      manager_approval: ([ldap_object[%s(mspki-enrollment-flag)].first.to_i].pack('l').unpack1('L') & Rex::Proto::MsCrtd::CT_FLAG_PEND_ALL_REQUESTS) != 0,
      required_signatures: [ldap_object[%s(mspki-ra-signature)].first.to_i].pack('l').unpack1('L'),
      notes: []
    }
  end

  def find_esc15_vuln_cert_templates
    esc_raw_filter = '(&'\
      '(objectclass=pkicertificatetemplate)'\
      '(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))'\
      '(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))'\
      '(pkiextendedkeyusage=*)'\
      '(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1)'\
      '(mspki-template-schema-version=1)'\
    ')'
    notes = [
      'ESC15: Request can specify a subjectAltName (msPKI-Certificate-Name-Flag) and EKUs can be altered (msPKI-Template-Schema-Version)'
    ]
    query_ldap_server_certificates(esc_raw_filter, 'ESC15', notes: notes)
  end

  # For ESC9, ESC10 and ESC16
  def users_compatible_with_template?(current_user, flag_values, users = nil)
    return false if flag_values.blank?

    raw = flag_values.is_a?(Array) ? flag_values.first : flag_values
    return false if raw.nil?

    mask = raw.to_i & 0xffffffff

    dns_required = (mask & CT_FLAG_SUBJECT_ALT_REQUIRE_DNS) != 0
    upn_required = (mask & CT_FLAG_SUBJECT_ALT_REQUIRE_UPN) != 0

    if dns_required && current_user.to_s.end_with?('$') && (users.blank? || users.any? { |user| user.end_with?('$') })
      true
    elsif upn_required && !current_user.to_s.end_with?('$') && (users.blank? || users.any? { |user| !user.end_with?('$') })
      true
    else
      false
    end
  end

  def find_esc16_vuln_cert_templates
    # if we were able to read the registry values and this OID is not explicitly disabled, then we know for certain the server is not vulnerable
    esc16_raw_filter = '(&'\
     '(|'\
    "(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=#{CT_FLAG_SUBJECT_ALT_REQUIRE_UPN})"\
    "(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=#{CT_FLAG_SUBJECT_ALT_REQUIRE_DNS})"\
    "(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=#{CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME})"\
     ')'\
      '(objectclass=pkicertificatetemplate)'\
      '(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))'\
      '(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))'\
      '(pkiextendedkeyusage=*)'\
    ')'

    esc_entries = query_ldap_server(esc16_raw_filter, CERTIFICATE_ATTRIBUTES + ['msPKI-Certificate-Name-Flag'], base_prefix: CERTIFICATE_TEMPLATES_BASE)
    return if esc_entries.empty?

    esc_entries.each do |entry|
      certificate_symbol = entry[:cn][0].to_sym

      # Get the CA servers that issue this template and we'll check their registry values
      @certificate_details[certificate_symbol][:ca_servers].each_value do |ca_server|
        ca_name = ca_server[:name].to_sym
        @certificate_details[certificate_symbol][:certificate_name_flags] = entry['mspki-certificate-name-flag']
        enroll_sids = @certificate_details[certificate_symbol][:enroll_sids]
        users = find_users_with_write_and_enroll_rights(enroll_sids)
        user_plural = users.size > 1 ? 'accounts' : 'account'
        has_plural = users.size > 1 ? 'have' : 'has'
        current_user = adds_get_current_user(@ldap)[:samaccountname].first
        @certificate_details[certificate_symbol][:target_users] = users

        # ESC16 revolves around the szOID_NTDS_CA_SECURITY_EXT being globally disabled on the CA server via the disable_extension_list. If it's not disabled, skip
        if vulnerable_to_esc16_1?(ca_name)
          next if users.empty?
          next unless users_compatible_with_template?(current_user, entry['mspki-certificate-name-flag'], users)

          note = "ESC16_1: The account: #{current_user} has edit permission over the #{user_plural}: #{users.join(', ')} which #{has_plural} enrollment rights for this template."
          note += " Registry values: StrongCertificateBindingEnforcement=#{@registry_values[:strong_certificate_binding_enforcement]}, CertificateMappingMethods=#{@registry_values[:certificate_mapping_methods]}."
          note += " The Certificate Authority: #{ca_name} has 1.3.6.1.4.1.311.25.2 defined in it's disabled extension list"

          # Scenario 1 - StrongCertificateBindingEnforcement = 1 or 0 then it's the same as ESC9 - mark them all as vulnerable
          @certificate_details[certificate_symbol][:techniques] << 'ESC16_1'
          @certificate_details[certificate_symbol][:notes] << note
        end

        if vulnerable_to_esc16_2?(ca_name)
          # Scenario 2 - StrongCertificateBindingEnforcement = 2 but the edit_flags contain EDITF_ATTRIBUTESUBJECTALTNAME2 which re-enables the ability to exploit the certificate in the same way as ESC6
          @certificate_details[certificate_symbol][:techniques] << 'ESC16_2'
          @certificate_details[certificate_symbol][:notes] << "ESC16_2: Template is vulnerable due to the active policy EditFlags having: EDITF_ATTRIBUTESUBJECTALTNAME2 set (which is essentially ESC6) on the Certificate Authority: #{ca_name}. Also the CA having 1.3.6.1.4.1.311.25.2 defined in it's disabled extension list"
        end

        next unless @registry_values.blank?
        # We couldn't read the registry values - mark as potentially vulnerable
        next unless users_compatible_with_template?(current_user, entry['mspki-certificate-name-flag'])

        @certificate_details[certificate_symbol][:techniques] << 'ESC16_2'
        @certificate_details[certificate_symbol][:notes] << 'ESC16_2: Template appears to be vulnerable (most templates do)'

        next if users.empty?
        next unless users_compatible_with_template?(current_user, entry['mspki-certificate-name-flag'], users)

        @certificate_details[certificate_symbol][:techniques] << 'ESC16_1'
        @certificate_details[certificate_symbol][:notes] << "ESC16_1: The account: #{current_user} has edit permission over the #{user_plural}: #{users.join(', ')} which #{has_plural} enrollment rights for this template."
      end
    end
  end

  def vulnerable_to_esc16_1?(ca_name)
    @registry_values[ca_name]&.[](:disable_extension_list)&.include?('1.3.6.1.4.1.311.25.2') && @registry_values[:strong_certificate_binding_enforcement] && (@registry_values[:strong_certificate_binding_enforcement] == 0 || @registry_values[:strong_certificate_binding_enforcement] == 1)
  end

  def vulnerable_to_esc16_2?(ca_name)
    @registry_values[ca_name]&.[](:disable_extension_list)&.include?('1.3.6.1.4.1.311.25.2') && @registry_values[ca_name][:edit_flags] & EDITF_ATTRIBUTESUBJECTALTNAME2 != 0 && @registry_values[:strong_certificate_binding_enforcement] && @registry_values[:strong_certificate_binding_enforcement] == 2
  end

  def find_enrollable_vuln_certificate_templates
    # For each of the vulnerable certificate templates, determine which servers
    # allows users to enroll in that certificate template and which users/groups
    # have permissions to enroll in certificates on each server.

    authority_details = {}
    @certificate_details.each_key do |certificate_template|
      certificate_enrollment_raw_filter = "(&(objectClass=pKIEnrollmentService)(certificateTemplates=#{ldap_escape_filter(certificate_template.to_s)}))"
      attributes = ['cn', 'name', 'dnsHostname', 'ntsecuritydescriptor']
      base_prefix = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration'
      enrollment_ca_data = query_ldap_server(certificate_enrollment_raw_filter, attributes, base_prefix: base_prefix)
      next if enrollment_ca_data.empty?

      enrollment_ca_data.each do |ldap_object|
        ca_server_key = ldap_object[:dnshostname].first.to_s.downcase.to_sym
        next if @certificate_details[certificate_template][:ca_servers].key?(ca_server_key)

        authority_details[ca_server_key] = @certificate_details[certificate_template][:ca_servers][ca_server_key] = authority_details.fetch(ca_server_key) { build_authority_details(ldap_object) }
      end
    end
  end

  def reporting_split_techniques(template)
    # these techniques are special in the sense that the exploit steps involve a different user performing the request
    # meaning that whether or not we can issue them is irrelevant
    enroll_by_proxy = %w[ESC9 ESC10 ESC16_1]
    # technically ESC15 might be patched and we can't fingerprint that status but we leave it in the "vulnerable" category

    # when we have the registry values, we can tell the vulnerabilities for certain
    if @registry_values.present?
      potentially_vulnerable = []
      vulnerable = template[:techniques].dup
    else
      # ESC16_2 doesn't require a separate user to enroll, so it does not belong in the enroll_by_proxy array
      # however should it should be reported as potentially vulnerable if we don't have registry data
      potentially_vulnerable = template[:techniques] & (enroll_by_proxy + ['ESC16_2'])
      vulnerable = template[:techniques] - potentially_vulnerable
    end

    if datastore['REPORT'] == 'vulnerable-and-enrollable'
      vulnerable.keep_if do |technique|
        enroll_by_proxy.include?(technique) || can_enroll?(template)
      end

      potentially_vulnerable.delete('ESC16_2') if potentially_vulnerable.include?('ESC16_2') && !can_enroll?(template)

    end

    [vulnerable, potentially_vulnerable]
  end

  def can_enroll?(template)
    (template[:permissions].include?('FULL CONTROL') || template[:permissions].include?('ENROLL')) && (template[:ca_servers].empty? || template[:ca_servers].values.any? { _1[:permissions].include?('REQUEST CERTIFICATES') })
  end

  def print_vulnerable_cert_info
    filtered_certificate_details = @certificate_details.sort.to_h.select do |_key, template|
      case datastore['REPORT']
      when 'all'
        true
      when 'published'
        template[:ca_servers].present?
      when 'enrollable'
        can_enroll?(template)
      when 'vulnerable'
        template[:techniques].present?
      when 'vulnerable-and-published'
        template[:techniques].present? && template[:ca_servers].present?
      when 'vulnerable-and-enrollable'
        !reporting_split_techniques(template).flatten.empty?
      end
    end

    any_esc3t1 = filtered_certificate_details.values.any? do |hash|
      hash[:techniques].include?('ESC3')
    end

    filtered_certificate_details.each do |key, hash|
      vulnerable_techniques, potentially_vulnerable_techniques = reporting_split_techniques(hash)
      all_techniques = vulnerable_techniques + potentially_vulnerable_techniques
      all_techniques.delete('ESC3_TEMPLATE_2') unless any_esc3t1 # don't report ESC3_TEMPLATE_2 if there are no instances of ESC3
      next unless all_techniques.present? || datastore['REPORT'] == 'all'

      if db
        all_techniques.each do |vuln|
          next if vuln == 'ESC3_TEMPLATE_2'

          prefix = "#{vuln}:"
          info = hash[:notes].select { |note| note.start_with?(prefix) }.map { |note| note.delete_prefix(prefix).strip }.join("\n")
          info = nil if info.blank?

          hash[:ca_servers].each_value do |ca_server|
            service = report_service(
              host: ca_server[:ip_address],
              port: 445,
              proto: 'tcp',
              name: 'AD CS',
              info: "AD CS CA name: #{ca_server[:name]}"
            )

            if ca_server[:ip_address].present?
              vuln = report_vuln(
                workspace: myworkspace,
                host: ca_server[:ip_address],
                port: 445,
                proto: 'tcp',
                sname: 'AD CS',
                name: "#{vuln} - #{key}",
                info: info,
                refs: REFERENCES[vuln],
                service: service
              )
            else
              vuln = nil
            end
          end
        end
      end

      print_good("Template: #{key}")

      print_status("  Distinguished Name: #{hash[:dn]}")
      print_status("  Manager Approval: #{hash[:manager_approval] ? '%redRequired' : '%grnDisabled'}%clr")
      print_status("  Required Signatures: #{hash[:required_signatures] == 0 ? '%grn0' : '%red' + hash[:required_signatures].to_s}%clr")

      if vulnerable_techniques.present?
        print_good("  Vulnerable to: #{vulnerable_techniques.join(', ')}")
      else
        print_status('  Vulnerable to: (none)')
      end

      if potentially_vulnerable_techniques.include?('ESC9')
        print_warning('  Potentially vulnerable to: ESC9 (the template is in a vulnerable configuration but in order to exploit registry key StrongCertificateBindingEnforcement must not be set to 2)')
      end
      if potentially_vulnerable_techniques.include?('ESC10')
        print_warning('  Potentially vulnerable to: ESC10 (the template is in a vulnerable configuration but in order to exploit registry key StrongCertificateBindingEnforcement must be set to 0 or CertificateMappingMethods must be set to 4)')
      end
      if potentially_vulnerable_techniques.include?('ESC16_1')
        print_warning('  Potentially vulnerable to: ESC16_1 (the template is in a vulnerable configuration but in order to exploit registry key StrongCertificateBindingEnforcement must be set to either 0 or 1 and the CA must have the SID security extention OID: 1.3.6.1.4.1.311.25.2 listed under the DisbaledExtensionlist registry key.')
      end
      if potentially_vulnerable_techniques.include?('ESC16_2')
        print_warning('  Potentially vulnerable to: ESC16_2 (the template is in a vulnerable configuration but in order to exploit registry key StrongCertificateBindingEnforcement must be set to 2 and the CA must have the SID security extention OID: 1.3.6.1.4.1.311.25.2 listed under the DisbaledExtensionlist registry key and EDITF_ATTRIBUTESUBJECTALTNAME2 enabled in the EditFlags policy).')
      end

      print_status("  Permissions: #{hash[:permissions].join(', ')}")

      if hash[:notes].present? && hash[:notes].length == 1
        print_status("  Notes: #{hash[:notes].first}")
      elsif hash[:notes].present? && hash[:notes].length > 1
        print_status('  Notes:')
        hash[:notes].each do |note|
          print_status("    * #{note}")
        end
      end

      if hash[:write_sids]
        print_status('  Certificate Template Write-Enabled SIDs:')
        hash[:write_sids].each do |sid|
          print_status("    * #{highlight_sid(sid)}")
        end
      end

      print_status('  Certificate Template Enrollment SIDs:')
      hash[:enroll_sids].each do |sid|
        print_status("    * #{highlight_sid(sid)}")
      end

      if hash[:ca_servers].any?
        hash[:ca_servers].each do |ca_fqdn, ca_hash|
          print_good("  Issuing CA: #{ca_hash[:name]} (#{ca_fqdn})")
          # Don't print the permissions here because it can be misleading since not all can be detected
          # see: #build_authority_details
          print_status('    Enrollment SIDs:')
          ca_hash[:enroll_sids].each do |sid|
            print_status("      * #{highlight_sid(sid)}")
          end
        end
      else
        print_warning('   Issuing CAs: none (not published as an enrollable certificate)')
      end
    end
  end

  def highlight_sid(sid)
    color = ''
    color = '%grn' if sid.value == WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
    if sid.value.starts_with?("#{WellKnownSids::SECURITY_NT_NON_UNIQUE}-")
      color = '%grn' if sid.rid == WellKnownSids::DOMAIN_GROUP_RID_USERS
      color = '%grn' if sid.rid == WellKnownSids::DOMAIN_GROUP_RID_GUESTS
      color = '%grn' if sid.rid == WellKnownSids::DOMAIN_GROUP_RID_COMPUTERS
    end
    "#{color}#{sid.value} (#{sid.name})%clr"
  end

  def get_pki_object_by_oid(oid)
    pki_object = @ldap_objects.find { |o| o['mspki-cert-template-oid']&.first == oid }

    if pki_object.nil?
      pki_object = query_ldap_server(
        "(&(objectClass=msPKI-Enterprise-Oid)(msPKI-Cert-Template-OID=#{ldap_escape_filter(oid.to_s)}))",
        nil,
        base_prefix: 'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration'
      )&.first
      @ldap_objects << pki_object if pki_object
    end

    pki_object
  end

  def get_group_by_dn(group_dn)
    group = @ldap_objects.find { |o| o['dn']&.first == group_dn }

    if group.nil?
      cn, _, base = group_dn.partition(',')
      base.delete_suffix!(",#{@base_dn}")
      group = query_ldap_server(
        "(#{cn})",
        nil,
        base_prefix: base
      )&.first
      @ldap_objects << group if group
    end

    group
  end

  def get_object_by_sid(object_sid)
    object_sid = Rex::Proto::MsDtyp::MsDtypSid.new(object_sid)
    object = @ldap_objects.find { |o| o['objectSID']&.first == object_sid.to_binary_s }

    if object.nil?
      object = query_ldap_server("(objectSID=#{ldap_escape_filter(object_sid.to_s)})", nil)&.first
      @ldap_objects << object if object
    end

    object
  end

  def get_ip_addresses_by_fqdn(host_fqdn)
    return @fqdns[host_fqdn] if @fqdns.key?(host_fqdn)

    vprint_status("Resolving addresses for #{host_fqdn} via DNS.")
    begin
      ip_addresses = Rex::Socket.getaddresses(host_fqdn)
    rescue ::SocketError
      print_warning("No IP addresses were found for #{host_fqdn} via DNS.")
    else
      @fqdns[host_fqdn] = ip_addresses
      vprint_status("Found #{ip_addresses.length} IP address#{ip_addresses.length > 1 ? 'es' : ''} via DNS.")
      return ip_addresses
    end

    vprint_status("Looking up DNS records for #{host_fqdn} in LDAP.")
    hostname, _, domain = host_fqdn.partition('.')
    begin
      results = query_ldap_server(
        "(&(objectClass=dnsNode)(DC=#{ldap_escape_filter(hostname)}))",
        %w[dnsRecord],
        base_prefix: "DC=#{ldap_escape_filter(domain)},CN=MicrosoftDNS,DC=DomainDnsZones"
      )
    rescue Msf::Auxiliary::Failed
      print_error('Encountered an error while querying LDAP for DNS records.')
      @fqdns[host_fqdn] = nil
    end
    return nil if results.blank?

    ip_addresses = []
    results.first[:dnsrecord].each do |packed|
      begin
        unpacked = MsDnspDnsRecord.read(packed)
      rescue ::EOFError
        next
      rescue ::IOError
        next
      end

      next unless [ DnsRecordType::DNS_TYPE_A, DnsRecordType::DNS_TYPE_AAAA ].include?(unpacked.record_type)

      ip_addresses << unpacked.data.to_s
    end

    @fqdns[host_fqdn] = ip_addresses
    if ip_addresses.empty?
      print_warning("No A or AAAA DNS records were found for #{host_fqdn} in LDAP.")
    else
      vprint_status("Found #{ip_addresses.length} IP address#{ip_addresses.length > 1 ? 'es' : ''} via A and AAAA DNS records.")
    end

    ip_addresses
  end

  def domain_controller_version_check
    domain = adds_get_domain_info(@ldap)[:dns_name]
    user = adds_get_current_user(@ldap)[:sAMAccountName].first.to_s
    print_status("user: #{user}, domain: #{domain}")

    version_raw = nil
    conn = create_winrm_connection(datastore['RHOSTS'], domain, user, datastore['WINRM_TIMEOUT'])
    # Get the build number over WinRM by querying the Update Build Revision from the registry and appending it to the OS version.
    # If there is no URB append 0 so we the string always ends in a numberical value
    conn.shell(:powershell) do |shell|
      ps = <<~PS
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $ubr = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name UBR -ErrorAction SilentlyContinue).UBR
        if ($ubr -eq $null) { $ubr = 0 }
        Write-Output ("{0}.{1}" -f $os.Version, $ubr)
      PS
      output = shell.run(ps)
      version_raw = output.stdout&.lines&.first&.strip
      shell.close
    end

    if version_raw.blank?
      print_error("Could not retrieve Windows version string from #{datastore['RHOSTS']} via WinRM.")
    end

    version_obj = Rex::Version.new(version_raw)

    print_status("Detected target Windows version: #{version_raw}")

    # Product ranges: [ Product name, RTM version, Sept2025 patch version ]
    # Replace the 'patch_version' entries with actual September 2025 version/build strings.
    ranges = [
      [Msf::WindowsVersion::ServerNameMapping[:Server2025], Msf::WindowsVersion::Server2025, Rex::Version.new('10.0.26100.6588')],
      [Msf::WindowsVersion::ServerNameMapping[:Server2022], Msf::WindowsVersion::Server2022, Rex::Version.new('10.0.20348.4171')],
      [Msf::WindowsVersion::ServerNameMapping[:Server2019], Msf::WindowsVersion::Server2019, Rex::Version.new('10.0.17763.7792')],
      [Msf::WindowsVersion::ServerNameMapping[:Server2016], Msf::WindowsVersion::Server2016, Rex::Version.new('10.0.14393.8422')],
    ]

    ranges.each do |product, rtm_version, patch_version|
      if version_obj >= rtm_version && version_obj < patch_version
        print_good("Detected #{product} version #{version_obj} — appears vulnerable (below Sept 2025 threshold #{patch_version}). Module will continue.")
        return false
      end

      if version_obj >= patch_version
        fail_with(Failure::NotVulnerable, "Detected #{product} version #{version_obj} which is at-or-above the September 2025 threshold (#{patch_version}). Target appears patched. Weak certificate mappings/ ESC techniques are not exploitable on this domain controller")
      end
    end

    print_error("Could not map detected Windows version #{version_obj} to a known product range.")
  end

  def set_can_enroll_flags
    @certificate_details.each_key do |certificate_template|
      @certificate_details[certificate_template][:can_enroll] = can_enroll?(@certificate_details[certificate_template])
    end
  end

  def validate
    super
    if (datastore['RUN_REGISTRY_CHECKS']) && !%w[auto plaintext ntlm].include?(datastore['LDAP::Auth'].downcase)
      raise Msf::OptionValidateError, ["RUN_REGISTRY_CHECKS is incompatible with LDAP::Auth type '#{datastore['LDAP::Auth']}'. Supported types are: plaintext, NTLM."]
    end
  end

  def run
    # Define our instance variables real quick.
    @base_dn = nil
    @ldap_objects = []
    @registry_values = {}
    @fqdns = {}
    @certificate_details = {} # Initialize to empty hash since we want to only keep one copy of each certificate template along with its details.

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

      # If the domain controller is patched up to Sept 2025, the CA can still issue Certificates which appear
      # vulnerable (ie. Subject Alt Names can be specified with UPN: Administrator) however the Domain controller no
      # longer accepts weak certificate mappings regardless of the StrongCertificateBindingEnforcement/ CertificaateMappingMethod registry key.
      begin
        domain_controller_version_check
      rescue WinRM::WinRMAuthorizationError => e
        print_warning("Unable to determine the version of Window so these all might be false postives! WinRM authorization error: #{e.message}")
      end

      templates = query_ldap_server('(objectClass=pkicertificatetemplate)', CERTIFICATE_ATTRIBUTES, base_prefix: CERTIFICATE_TEMPLATES_BASE)
      fail_with(Failure::NotFound, 'No certificate templates were found.') if templates.empty?

      templates.each do |template|
        certificate_symbol = template[:cn].first.to_sym
        @certificate_details[certificate_symbol] = build_template_details(template)
      end

      registry_values = enum_registry_values if datastore['RUN_REGISTRY_CHECKS']

      if registry_values&.any?
        registry_values.each do |key, value|
          vprint_good("#{key}: #{value.inspect}")
        end
      end

      find_enrollable_vuln_certificate_templates
      set_can_enroll_flags
      find_esc1_vuln_cert_templates
      find_esc2_vuln_cert_templates
      find_esc3_vuln_cert_templates
      find_esc4_vuln_cert_templates

      if registry_values.blank?
        find_esc9_vuln_cert_templates
        find_esc10_vuln_cert_templates
      else
        if registry_values[:strong_certificate_binding_enforcement] != 2
          find_esc9_vuln_cert_templates
        end
        if registry_values[:strong_certificate_binding_enforcement] == 1 || registry_values[:certificate_mapping_methods] & 4 > 0
          find_esc10_vuln_cert_templates
        end
      end

      find_esc13_vuln_cert_templates
      find_esc15_vuln_cert_templates
      find_esc16_vuln_cert_templates

      print_vulnerable_cert_info

      @certificate_details
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
end
