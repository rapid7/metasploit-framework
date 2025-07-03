class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP
  include Rex::Proto::MsDnsp
  include Rex::Proto::Secauthz
  include Rex::Proto::LDAP

  ADS_GROUP_TYPE_BUILTIN_LOCAL_GROUP = 0x00000001
  ADS_GROUP_TYPE_GLOBAL_GROUP = 0x00000002
  ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP = 0x00000004
  ADS_GROUP_TYPE_SECURITY_ENABLED = 0x80000000
  ADS_GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008

  REFERENCES = {
    'ESC1' => [ SiteReference.new('URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2') ],
    'ESC2' => [ SiteReference.new('URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2') ],
    'ESC3' => [ SiteReference.new('URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2') ],
    'ESC4' => [ SiteReference.new('URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2') ],
    'ESC13' => [ SiteReference.new('URL', 'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53') ],
    'ESC15' => [ SiteReference.new('URL', 'https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc') ]
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
        },
        'Author' => [
          'Grant Willcox', # Original module author
          'Spencer McIntyre', # ESC13 and ESC15 updates
          'jheysel-r7' # ESC4 update
        ],
        'References' => REFERENCES.values.flatten.map { |r| [ r.ctx_id, r.ctx_val ] }.uniq,
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
      OptBool.new('REPORT_NONENROLLABLE', [true, 'Report nonenrollable certificate templates', false]),
      OptBool.new('REPORT_PRIVENROLLABLE', [true, 'Report certificate templates restricted to domain and enterprise admins', false]),
    ])
  end

  # Constants Definition
  CERTIFICATE_ATTRIBUTES = %w[cn name description nTSecurityDescriptor msPKI-Certificate-Policy msPKI-Enrollment-Flag msPKI-RA-Signature msPKI-Template-Schema-Version pkiExtendedKeyUsage]
  CERTIFICATE_TEMPLATES_BASE = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration'.freeze
  CERTIFICATE_ENROLLMENT_EXTENDED_RIGHT = '0e10c968-78fb-11d2-90d4-00c04f79dc55'.freeze
  CERTIFICATE_AUTOENROLLMENT_EXTENDED_RIGHT = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'.freeze
  CONTROL_ACCESS = 0x00000100

  # LDAP_SERVER_SD_FLAGS constant definition, taken from https://ldapwiki.com/wiki/LDAP_SERVER_SD_FLAGS_OID
  LDAP_SERVER_SD_FLAGS_OID = '1.2.840.113556.1.4.801'.freeze
  OWNER_SECURITY_INFORMATION = 0x1
  GROUP_SECURITY_INFORMATION = 0x2
  DACL_SECURITY_INFORMATION = 0x4
  SACL_SECURITY_INFORMATION = 0x8

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
    enum_acl_aces(acl) do |ace_type_name, ace|
      # To decode the ObjectType we need to do another query to CN=Configuration,DC=daforest,DC=com
      # and look at either schemaIDGUID or rightsGUID fields to see if they match this value.
      if (object_type = ace[:body][:object_type]) && !(object_type == CERTIFICATE_ENROLLMENT_EXTENDED_RIGHT || object_type == CERTIFICATE_AUTOENROLLMENT_EXTENDED_RIGHT)
        # If an object type was specified, only process the rest if it is one of these two (note that objects with no
        # object types will be processed to make sure we can detect vulnerable templates post exploiting ESC4).
        next
      end

      # Skip entry if it is not related to an extended access control right, where extended access control right is
      # described as ADS_RIGHT_DS_CONTROL_ACCESS in the ObjectType field of ACCESS_ALLOWED_OBJECT_ACE. This is
      # detailed further at https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace
      next unless (ace[:body].access_mask.protocol & CONTROL_ACCESS) == CONTROL_ACCESS

      if ace_type_name.match(/ALLOWED/)
        allowed_sids << ace[:body][:sid]
      end
    end

    map_sids_to_names(allowed_sids)
  end

  # This will return a list of SIDs that can edit the template from which the ACL is derived
  # The method checks the WriteOwner, WriteDacl and GenericWrite bits of the access_mask to see if the user or group has write permissions over the Certificate
  def get_sids_for_write(acl)
    allowed_sids = []

    enum_acl_aces(acl) do |_ace_type_name, ace|
      # Look at WriteOwner, WriteDacl and GenericWrite to see if the user has write permissions over the Certificate
      if !(ace[:body][:access_mask][:wo] == 1 || ace[:body][:access_mask][:wd] == 1 || ace[:body][:access_mask][:gw] == 1)
        next
      end

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

    # Set the value of LDAP_SERVER_SD_FLAGS_OID flag so everything but
    # the SACL flag is set, as we need administrative privileges to retrieve
    # the SACL from the ntSecurityDescriptor attribute on Windows AD LDAP servers.
    #
    # Note that without specifying the LDAP_SERVER_SD_FLAGS_OID control in this manner,
    # the LDAP searchRequest will default to trying to grab all possible attributes of
    # the ntSecurityDescriptor attribute, hence resulting in an attempt to retrieve the
    # SACL even if the user is not an administrative user.
    #
    # Now one may think that we would just get the rest of the data without the SACL field,
    # however in reality LDAP will cause that attribute to just be blanked out if a part of it
    # cannot be retrieved, so we just will get nothing for the ntSecurityDescriptor attribute
    # in these cases if the user doesn't have permissions to read the SACL.
    all_but_sacl_flag = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    control_values = [all_but_sacl_flag].map(&:to_ber).to_ber_sequence.to_s.to_ber
    controls = []
    controls << [LDAP_SERVER_SD_FLAGS_OID.to_ber, true.to_ber, control_values].to_ber_sequence

    returned_entries = @ldap.search(base: full_base_dn, filter: filter, attributes: attributes, controls: controls)
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
      next if @certificate_details[certificate_symbol][:enroll_sids].empty?

      @certificate_details[certificate_symbol][:techniques] << esc_id
      @certificate_details[certificate_symbol][:notes] += notes
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
    # Determine who we are authenticating with. Retrieve the username and user SID
    whoami_response = ''
    begin
      whoami_response = @ldap.ldapwhoami
    rescue Net::LDAP::Error => e
      print_warning("The module failed to run the ldapwhoami command, ESC4 detection can't continue. Error was: #{e.class}: #{e.message}.")
      return
    end

    if whoami_response.empty?
      print_error("Unable to retrieve the username using ldapwhoami, ESC4 detection can't continue")
      return
    end

    sam_account_name = whoami_response.split('\\')[1]
    user_raw_filter = "(sAMAccountName=#{sam_account_name})"
    attributes = ['DN', 'objectSID', 'objectClass', 'primarygroupID']
    our_account = query_ldap_server(user_raw_filter, attributes)&.first
    if our_account.nil?
      print_warning("Unable to determine the User SID for #{sam_account_name}, ESC4 detection can't continue")
      return
    end

    user_sid = map_sids_to_names([Rex::Proto::MsDtyp::MsDtypSid.read(our_account[:objectsid].first).value]).first
    domain_sid = user_sid.value.to_s.rpartition('-').first
    user_groups = []

    if our_account[:primarygroupID]
      user_groups << "#{domain_sid}-#{our_account[:primarygroupID]&.first}"
    end

    # Authenticated Users includes all users and computers with identities that have been authenticated.
    # Authenticated Users doesn't include Guest even if the Guest account has a password.
    unless sam_account_name == 'Guest'
      user_groups << Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
    end

    # Perform an LDAP query to get the groups the user is a part of
    # Use LDAP_MATCHING_RULE_IN_CHAIN OID in order to walk the chain of ancestry of groups.
    # https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax?redirectedfrom=MSDN
    filter_with_user = "(|(member:1.2.840.113556.1.4.1941:=#{our_account[:dn].first})"
    user_groups.each do |sid|
      obj = get_object_by_sid(sid)
      print_error('Failed to lookup SID.') unless obj

      filter_with_user << "(member:1.2.840.113556.1.4.1941:=#{obj[:dn].first})" if obj
    end
    filter_with_user << ')'

    attributes = ['cn', 'objectSID']
    esc_entries = query_ldap_server(filter_with_user, attributes)

    esc_entries.each do |entry|
      group_sid = Rex::Proto::MsDtyp::MsDtypSid.read(entry['ObjectSid'].first).value
      user_groups << group_sid
    end
    user_groups = map_sids_to_names(user_groups)

    # Determine what Certificate Templates are available to us
    esc_raw_filter = '(objectclass=pkicertificatetemplate)'

    attributes = ['cn', 'description', 'ntSecurityDescriptor']
    esc_entries = query_ldap_server(esc_raw_filter, attributes, base_prefix: CERTIFICATE_TEMPLATES_BASE)

    return if esc_entries.empty?

    # Determine if the user we've authenticated with has the ability to edit
    esc_entries.each do |entry|
      certificate_symbol = entry[:cn][0].to_sym
      next if @certificate_details[certificate_symbol][:enroll_sids].empty?

      # SIDs that can edit the template
      write_priv_sids = @certificate_details[certificate_symbol][:write_sids]
      next if write_priv_sids.empty?

      # Check if the user has been give access to edit the template
      user_can_edit = user_sid if write_priv_sids.include?(user_sid)

      # Check if any groups the user is a part of can edit the template
      group_can_edit = write_priv_sids & user_groups

      # SIDs that can edit the template that the user we've authenticated with are also a part of
      user_write_priv_sids = []
      notes = []

      # Main reason for splitting user_can_edit and group_can_edit is so "note" can be more descriptive
      if user_can_edit
        user_write_priv_sids << user_can_edit
        notes << "ESC4: The account: #{sam_account_name} has edit permissions over the template #{certificate_symbol} making it vulnerable to ESC4"
      end

      if group_can_edit.any?
        user_write_priv_sids.concat(group_can_edit)
        notes << "ESC4: The account: #{sam_account_name} is a part of the following groups: (#{group_can_edit.map(&:name).join(', ')}) which have edit permissions over the template object"
      end

      next unless user_write_priv_sids.any?

      @certificate_details[certificate_symbol][:techniques] << 'ESC4'
      @certificate_details[certificate_symbol][:notes].concat(notes)
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
      certificate_symbol = entry[:cn][0].to_sym
      next if @certificate_details[certificate_symbol][:enroll_sids].empty?

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

  def build_certificate_details(ldap_object, techniques: [], notes: [])
    security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(ldap_object[:ntsecuritydescriptor].first)

    if security_descriptor.dacl
      enroll_sids = get_sids_for_enroll(security_descriptor.dacl)
      write_sids = get_sids_for_write(security_descriptor.dacl)
    else
      enroll_sids = nil
      write_sids = nil
    end

    {
      name: ldap_object[:cn][0].to_s,
      techniques: techniques,
      dn: ldap_object[:dn][0].to_s,
      enroll_sids: enroll_sids,
      write_sids: write_sids,
      security_descriptor: security_descriptor,
      ekus: ldap_object[:pkiextendedkeyusage].map(&:to_s),
      schema_version: ldap_object[%s(mspki-template-schema-version)].first,
      ca_servers: {},
      manager_approval: ([ldap_object[%s(mspki-enrollment-flag)].first.to_i].pack('l').unpack1('L') & Rex::Proto::MsCrtd::CT_FLAG_PEND_ALL_REQUESTS) != 0,
      required_signatures: [ldap_object[%s(mspki-ra-signature)].first.to_i].pack('l').unpack1('L'),
      notes: notes
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

  def find_enrollable_vuln_certificate_templates
    # For each of the vulnerable certificate templates, determine which servers
    # allows users to enroll in that certificate template and which users/groups
    # have permissions to enroll in certificates on each server.

    @certificate_details.each_key do |certificate_template|
      certificate_enrollment_raw_filter = "(&(objectClass=pKIEnrollmentService)(certificateTemplates=#{ldap_escape_filter(certificate_template.to_s)}))"
      attributes = ['cn', 'name', 'dnsHostname', 'ntsecuritydescriptor']
      base_prefix = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration'
      enrollment_ca_data = query_ldap_server(certificate_enrollment_raw_filter, attributes, base_prefix: base_prefix)
      next if enrollment_ca_data.empty?

      enrollment_ca_data.each do |ca_server|
        begin
          security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(ca_server[:ntsecuritydescriptor][0])
        rescue IOError => e
          fail_with(Failure::UnexpectedReply, "Unable to read security descriptor! Error was: #{e.message}")
        end

        enroll_sids = get_sids_for_enroll(security_descriptor.dacl) if security_descriptor.dacl
        next if enroll_sids.empty?

        ca_server_fqdn = ca_server[:dnshostname][0].to_s.downcase
        unless ca_server_fqdn.blank?
          ca_server_ip_address = get_ip_addresses_by_fqdn(ca_server_fqdn)&.first

          if ca_server_ip_address
            report_service({
              host: ca_server_ip_address,
              port: 445,
              proto: 'tcp',
              name: 'AD CS',
              info: "AD CS CA name: #{ca_server[:name][0]}"
            })

            report_host({
              host: ca_server_ip_address,
              name: ca_server_fqdn
            })
          end
        end

        ca_server_key = ca_server_fqdn.to_sym
        next if @certificate_details[certificate_template][:ca_servers].key?(ca_server_key)

        @certificate_details[certificate_template][:ca_servers][ca_server_key] = {
          fqdn: ca_server_fqdn,
          ip_address: ca_server_ip_address,
          enroll_sids: enroll_sids,
          name: ca_server[:name][0].to_s,
          dn: ca_server[:dn][0].to_s
        }
      end
    end
  end

  def print_vulnerable_cert_info
    vuln_certificate_details = @certificate_details.sort.to_h.select do |_key, hash|
      select = true
      select = false unless datastore['REPORT_PRIVENROLLABLE'] || hash[:enroll_sids].any? do |sid|
        # compare based on RIDs to avoid issues language specific issues
        !(sid.value.starts_with?("#{WellKnownSids::SECURITY_NT_NON_UNIQUE}-") && [
          # RID checks
          WellKnownSids::DOMAIN_GROUP_RID_ADMINS,
          WellKnownSids::DOMAIN_GROUP_RID_ENTERPRISE_ADMINS,
          WellKnownSids::DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS,
          WellKnownSids::DOMAIN_GROUP_RID_CONTROLLERS,
          WellKnownSids::DOMAIN_GROUP_RID_SCHEMA_ADMINS
        ].include?(sid.rid)) && ![
          # SID checks
          WellKnownSids::SECURITY_ENTERPRISE_CONTROLLERS_SID
        ].include?(sid.value)
      end

      select = false unless datastore['REPORT_NONENROLLABLE'] || hash[:ca_servers].any?
      select
    end

    any_esc3t1 = vuln_certificate_details.values.any? do |hash|
      hash[:techniques].include?('ESC3') && (datastore['REPORT_NONENROLLABLE'] || hash[:ca_servers].any?)
    end

    vuln_certificate_details.each do |key, hash|
      techniques = hash[:techniques].dup
      techniques.delete('ESC3_TEMPLATE_2') unless any_esc3t1 # don't report ESC3_TEMPLATE_2 if there are no instances of ESC3
      next if techniques.empty?

      if db
        techniques.each do |vuln|
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
      print_good("  Vulnerable to: #{techniques.join(', ')}")
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
    object = @ldap_objects.find { |o| o['objectSID'].first == object_sid.to_binary_s }

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

  def run
    # Define our instance variables real quick.
    @base_dn = nil
    @ldap_objects = []
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

      templates = query_ldap_server('(objectClass=pkicertificatetemplate)', CERTIFICATE_ATTRIBUTES, base_prefix: CERTIFICATE_TEMPLATES_BASE)
      fail_with(Failure::NotFound, 'No certificate templates were found.') if templates.empty?

      templates.each do |template|
        certificate_symbol = template[:cn].first.to_sym
        @certificate_details[certificate_symbol] = build_certificate_details(template)
      end

      find_esc1_vuln_cert_templates
      find_esc2_vuln_cert_templates
      find_esc3_vuln_cert_templates
      find_esc4_vuln_cert_templates
      find_esc13_vuln_cert_templates
      find_esc15_vuln_cert_templates

      find_enrollable_vuln_certificate_templates
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
