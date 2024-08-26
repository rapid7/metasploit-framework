class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP
  include Rex::Proto::Secauthz

  ADS_GROUP_TYPE_BUILTIN_LOCAL_GROUP = 0x00000001
  ADS_GROUP_TYPE_GLOBAL_GROUP = 0x00000002
  ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP = 0x00000004
  ADS_GROUP_TYPE_SECURITY_ENABLED = 0x80000000
  ADS_GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008

  SID = Struct.new(:value, :name) do
    def to_s
      name.present? ? "#{value} (#{name})" : value
    end

    def rid
      value.split('-').last.to_i
    end
  end

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

          Currently the module is capable of checking for certificates that are vulnerable to ESC1, ESC2, ESC3, and
          ESC13. The module is limited to checking for these techniques due to them being identifiable remotely from a
          normal user account by analyzing the objects in LDAP.
        },
        'Author' => [
          'Grant Willcox', # Original module author
          'Spencer McIntyre' # ESC13 update
        ],
        'References' => [
          [ 'URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' ],
          [ 'URL', 'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53' ] # ESC13
        ],
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
  CERTIFICATE_ENROLLMENT_EXTENDED_RIGHT = '0e10c968-78fb-11d2-90d4-00c04f79dc55'.freeze
  CERTIFICATE_AUTOENROLLMENT_EXTENDED_RIGHT = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'.freeze
  CONTROL_ACCESS = 0x00000100

  # LDAP_SERVER_SD_FLAGS constant definition, taken from https://ldapwiki.com/wiki/LDAP_SERVER_SD_FLAGS_OID
  LDAP_SERVER_SD_FLAGS_OID = '1.2.840.113556.1.4.801'.freeze
  OWNER_SECURITY_INFORMATION = 0x1
  GROUP_SECURITY_INFORMATION = 0x2
  DACL_SECURITY_INFORMATION = 0x4
  SACL_SECURITY_INFORMATION = 0x8

  def parse_acl(acl)
    allowed_sids = []
    acl.aces.each do |ace|
      ace_header = ace[:header]
      ace_body = ace[:body]
      if ace_body[:access_mask].blank?
        fail_with(Failure::UnexpectedReply, 'Encountered a DACL/SACL object without an access mask! Either data is an unrecognized type or we are reading it wrong!')
      end
      ace_type_name = Rex::Proto::MsDtyp::MsDtypAceType.name(ace_header[:ace_type])
      if ace_type_name.blank?
        print_error("Skipping unexpected ACE of type #{ace_header[:ace_type]}. Either the data was read incorrectly or we currently don't support this type.")
        next
      end
      if ace_header[:ace_flags][:inherit_only_ace] == 1
        vprint_warning('      ACE only affects those that inherit from it, not those that it is attached to. Ignoring this ACE, as its not relevant.')
        next
      end

      # To decode the ObjectType we need to do another query to CN=Configuration,DC=daforest,DC=com
      # and look at either schemaIDGUID or rightsGUID fields to see if they match this value.
      if (object_type = ace_body[:object_type]) && !(object_type == CERTIFICATE_ENROLLMENT_EXTENDED_RIGHT || object_type == CERTIFICATE_AUTOENROLLMENT_EXTENDED_RIGHT)
        # If an object type was specified, only process the rest if it is one of these two (note that objects with no
        # object types will be processed to make sure we can detect vulnerable templates post exploiting ESC4).
        next
      end

      # Skip entry if it is not related to an extended access control right, where extended access control right is
      # described as ADS_RIGHT_DS_CONTROL_ACCESS in the ObjectType field of ACCESS_ALLOWED_OBJECT_ACE. This is
      # detailed further at https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace
      next unless (ace_body.access_mask.protocol & CONTROL_ACCESS) == CONTROL_ACCESS

      if ace_type_name.match(/ALLOWED/)
        allowed_sids << ace_body[:sid].to_s
      end
    end

    allowed_sids
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

  def query_ldap_server_certificates(esc_raw_filter, esc_name, notes: [])
    attributes = ['cn', 'description', 'ntSecurityDescriptor', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'PkiExtendedKeyUsage']
    base_prefix = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration'
    esc_entries = query_ldap_server(esc_raw_filter, attributes, base_prefix: base_prefix)

    if esc_entries.empty?
      print_warning("Couldn't find any vulnerable #{esc_name} templates!")
      return
    end

    # Grab a list of certificates that contain vulnerable settings.
    # Also print out the list of SIDs that can enroll in that server.
    esc_entries.each do |entry|
      begin
        security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(entry[:ntsecuritydescriptor][0])
      rescue IOError => e
        fail_with(Failure::UnexpectedReply, "Unable to read security descriptor! Error was: #{e.message}")
      end

      allowed_sids = parse_acl(security_descriptor.dacl) if security_descriptor.dacl
      next if allowed_sids.empty?
      next if allowed_sids.empty?

      certificate_symbol = entry[:cn][0].to_sym
      if @vuln_certificate_details.key?(certificate_symbol)
        @vuln_certificate_details[certificate_symbol][:vulns] << esc_name
        @vuln_certificate_details[certificate_symbol][:notes] += notes
      else
        @vuln_certificate_details[certificate_symbol] = {
          vulns: [esc_name],
          dn: entry[:dn][0],
          certificate_enrollment_sids: convert_sids_to_human_readable_name(allowed_sids),
          ca_servers_n_enrollment_sids: {},
          manager_approval: ([entry[%s(mspki-enrollment-flag)].first.to_i].pack('l').unpack1('L') & Rex::Proto::MsCrtd::CT_FLAG_PEND_ALL_REQUESTS) != 0,
          required_signatures: [entry[%s(mspki-ra-signature)].first.to_i].pack('l').unpack1('L'),
          notes: notes
        }
      end
    end
  end

  def convert_sids_to_human_readable_name(sids_array)
    output = []
    for sid in sids_array
      raw_filter = "(objectSID=#{ldap_escape_filter(sid.to_s)})"
      attributes = ['sAMAccountName', 'name']
      base_prefix = 'CN=Configuration'
      sid_entry = query_ldap_server(raw_filter, attributes, base_prefix: base_prefix) # First try with prefix to find entries that may be group specific.
      sid_entry = query_ldap_server(raw_filter, attributes) if sid_entry.empty? # Retry without prefix if blank.
      if sid_entry.empty?
        print_warning("Could not find any details on the LDAP server for SID #{sid}!")
        output << [sid, nil, nil] # Still want to print out the SID even if we couldn't get additional information.
      elsif sid_entry[0][:samaccountname][0]
        output << [sid, sid_entry[0][:name][0], sid_entry[0][:samaccountname][0]]
      else
        output << [sid, sid_entry[0][:name][0], nil]
      end
    end

    results = []
    output.each do |sid_string, sid_name, sam_account_name|
      results << SID.new(sid_string, sam_account_name || sid_name)
    end

    results
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
      'ESC1: Request can specify a subjectAltName (msPKI-Certificate-Name-Flag)'
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
    query_ldap_server_certificates(esc3_template_1_raw_filter, 'ESC3_TEMPLATE_1', notes: notes)

    # Find the second vulnerable types of ESC3 templates, those that
    # have the right template schema version and, for those with a template
    # version of 2 or greater, have an Application Policy Insurance Requirement
    # requiring the Certificate Request Agent EKU.
    #
    # Additionally the certificate template must also allow for domain authentication
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

  def find_esc13_vuln_cert_templates
    esc_raw_filter = <<~FILTER
      (&
        (objectclass=pkicertificatetemplate)
        (!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))
        (|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))
        (mspki-certificate-policy=*)
      )
    FILTER
    attributes = ['cn', 'description', 'ntSecurityDescriptor', 'msPKI-Certificate-Policy']
    base_prefix = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration'
    esc_entries = query_ldap_server(esc_raw_filter, attributes, base_prefix: base_prefix)

    if esc_entries.empty?
      print_warning("Couldn't find any vulnerable ESC13 templates!")
      return
    end

    # Grab a list of certificates that contain vulnerable settings.
    # Also print out the list of SIDs that can enroll in that server.
    esc_entries.each do |entry|
      begin
        security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(entry[:ntsecuritydescriptor][0])
      rescue IOError => e
        fail_with(Failure::UnexpectedReply, "Unable to read security descriptor! Error was: #{e.message}")
      end

      allowed_sids = parse_acl(security_descriptor.dacl) if security_descriptor.dacl
      next if allowed_sids.empty?

      groups = []
      entry['mspki-certificate-policy'].each do |certificate_policy_oid|
        policy = get_pki_object_by_oid(certificate_policy_oid)
        next if policy['msds-oidtogrouplink'].blank?

        # get the group and check it for two conditions
        group = get_group_by_dn(policy['msds-oidtogrouplink'].first)

        # condition 1: the group must be a universal group
        next if (group['grouptype'].first.to_i & ADS_GROUP_TYPE_UNIVERSAL_GROUP) == 0

        # condition 2: the group must have no members (this is enforced in the GUI but check it anyways)
        next if group['member'].present?

        groups << group['samaccountname'].first.to_s
      end
      next if groups.empty?

      note = "ESC13 groups: #{groups.join(', ')}"
      certificate_symbol = entry[:cn][0].to_sym
      if @vuln_certificate_details.key?(certificate_symbol)
        @vuln_certificate_details[certificate_symbol][:vulns] << 'ESC13'
        @vuln_certificate_details[certificate_symbol][:notes] << note
      else
        @vuln_certificate_details[certificate_symbol] = { vulns: ['ESC13'], dn: entry[:dn][0], certificate_enrollment_sids: convert_sids_to_human_readable_name(allowed_sids), ca_servers_n_enrollment_sids: {}, notes: [note] }
      end
    end
  end

  def find_enrollable_vuln_certificate_templates
    # For each of the vulnerable certificate templates, determine which servers
    # allows users to enroll in that certificate template and which users/groups
    # have permissions to enroll in certificates on each server.

    @vuln_certificate_details.each_key do |certificate_template|
      certificate_enrollment_raw_filter = "(&(objectClass=pKIEnrollmentService)(certificateTemplates=#{ldap_escape_filter(certificate_template.to_s)}))"
      attributes = ['cn', 'dnsHostname', 'ntsecuritydescriptor']
      base_prefix = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration'
      enrollment_ca_data = query_ldap_server(certificate_enrollment_raw_filter, attributes, base_prefix: base_prefix)
      next if enrollment_ca_data.empty?

      enrollment_ca_data.each do |ca_server|
        begin
          security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(ca_server[:ntsecuritydescriptor][0])
        rescue IOError => e
          fail_with(Failure::UnexpectedReply, "Unable to read security descriptor! Error was: #{e.message}")
        end

        allowed_sids = parse_acl(security_descriptor.dacl) if security_descriptor.dacl
        next if allowed_sids.empty?

        ca_server_key = ca_server[:dnshostname][0].to_sym
        unless @vuln_certificate_details[certificate_template][:ca_servers_n_enrollment_sids].key?(ca_server_key)
          @vuln_certificate_details[certificate_template][:ca_servers_n_enrollment_sids][ca_server_key] = { cn: ca_server[:cn][0], ca_enrollment_sids: allowed_sids }
        end
      end
    end
  end

  def print_vulnerable_cert_info
    vuln_certificate_details = @vuln_certificate_details.select do |_key, hash|
      select = true
      select = false unless datastore['REPORT_PRIVENROLLABLE'] || hash[:certificate_enrollment_sids].any? do |sid|
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

      select = false unless datastore['REPORT_NONENROLLABLE'] || hash[:ca_servers_n_enrollment_sids].any?
      select
    end

    any_esc3t1 = vuln_certificate_details.values.any? do |hash|
      hash[:vulns].include?('ESC3_TEMPLATE_1') && (datastore['REPORT_NONENROLLABLE'] || hash[:ca_servers_n_enrollment_sids].any?)
    end

    vuln_certificate_details.each do |key, hash|
      vulns = hash[:vulns]
      vulns.delete('ESC3_TEMPLATE_2') unless any_esc3t1 # don't report ESC3_TEMPLATE_2 if there are no instances of ESC3_TEMPLATE_1
      next if vulns.empty?

      print_good("Template: #{key}")

      print_status("  Distinguished Name: #{hash[:dn]}")
      print_status("  Manager Approval: #{hash[:manager_approval] ? '%redRequired' : '%grnDisabled'}%clr")
      print_status("  Required Signatures: #{hash[:required_signatures] == 0 ? '%grn0' : '%red' + hash[:required_signatures].to_s}%clr")
      print_good("  Vulnerable to: #{vulns.join(', ')}")
      if hash[:notes].present? && hash[:notes].length == 1
        print_status("  Notes: #{hash[:notes].first}")
      elsif hash[:notes].present? && hash[:notes].length > 1
        print_status('  Notes:')
        hash[:notes].each do |note|
          print_status("    * #{note}")
        end
      end

      print_status('  Certificate Template Enrollment SIDs:')
      hash[:certificate_enrollment_sids].each do |sid|
        print_status("    * #{highlight_sid(sid)}")
      end

      if hash[:ca_servers_n_enrollment_sids].any?
        hash[:ca_servers_n_enrollment_sids].each do |ca_hostname, ca_hash|
          print_good("  Issuing CA: #{ca_hash[:cn]} (#{ca_hostname})")
          print_status('    Enrollment SIDs:')
          convert_sids_to_human_readable_name(ca_hash[:ca_enrollment_sids]).each do |sid|
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
    pki_object = @ldap_mspki_enterprise_oids.find { |o| o['mspki-cert-template-oid'].first == oid }

    if pki_object.nil?
      pki_object = query_ldap_server(
        "(&(objectClass=msPKI-Enterprise-Oid)(msPKI-Cert-Template-OID=#{ldap_escape_filter(oid.to_s)}))",
        nil,
        base_prefix: 'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration'
      )&.first
      @ldap_mspki_enterprise_oids << pki_object if pki_object
    end

    pki_object
  end

  def get_group_by_dn(group_dn)
    group = @ldap_groups.find { |o| o['dn'].first == group_dn }

    if group.nil?
      cn, _, base = group_dn.partition(',')
      base.delete_suffix!(",#{@base_dn}")
      group = query_ldap_server(
        "(#{cn})",
        nil,
        base_prefix: base
      )&.first
      @ldap_groups << group if group
    end

    group
  end

  def run
    # Define our instance variables real quick.
    @base_dn = nil
    @ldap_mspki_enterprise_oids = []
    @ldap_groups = []
    @vuln_certificate_details = {} # Initialize to empty hash since we want to only keep one copy of each certificate template along with its details.

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

      find_esc1_vuln_cert_templates
      find_esc2_vuln_cert_templates
      find_esc3_vuln_cert_templates
      find_esc13_vuln_cert_templates

      find_enrollable_vuln_certificate_templates
      print_vulnerable_cert_info
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
