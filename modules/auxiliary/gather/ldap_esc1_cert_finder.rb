class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ESC1 Misconfigured Certificate Template Finder',
        'Description' => %q{
          This module allows users to query a LDAP server for ESC1 vulnerable certificate
          templates and will print these certificates out along with their associated permissions.

          ESC1 vulnerable certificates are those that allow users the ability to specify the
          SubjectAlternativeName field, also known as the SAN for short, when sending a certificate
          signing request to certificate authority server to create a new certificate using
          the vulnerable certificate template.

          By allowing non-privileged users the ability to specify the SAN for a certificate, these
          vulnerable certificate templates can be used by attackers to generate a new certificate
          which authorizes them as the user of their choice, which can be anyone that the certificate
          authority server recognizes as a valid user.
        },
        'Author' => [
          'Grant Willcox', # Original module author
        ],
        'References' => [
          'URL' => 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
        ],
        'DisclosureDate' => '2021-06-17',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it'])
    ])
  end

  # Constants Definition
  CERTIFICATE_ENROLLMENT_EXTENDED_RIGHT = '0e10c968-78fb-11d2-90d4-00c04f79dc55'.freeze
  CERTIFICATE_AUTOENROLLMENT_EXTENDED_RIGHT = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'.freeze

  def decode_certificate_name_flag(flag)
    raw_string = ''
    flag = flag.to_i

    if (flag & 0x00000001) == 0x00000001
      raw_string += 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT|'
    end
    if (flag & 0x00000008) == 0x00000008
      raw_string += 'CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME|'
    end
    if (flag & 0x00010000) == 0x00010000
      raw_string += 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME|'
    end
    if (flag & 0x00400000) == 0x00400000
      raw_string += 'CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS|'
    end
    if (flag & 0x00800000) == 0x00800000
      raw_string += 'CT_FLAG_SUBJECT_ALT_REQUIRE_SPN|'
    end
    if (flag & 0x01000000) == 0x01000000
      raw_string += 'CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID|'
    end
    if (flag & 0x02000000) == 0x02000000
      raw_string += 'CT_FLAG_SUBJECT_ALT_REQUIRE_UPN|'
    end
    if (flag & 0x04000000) == 0x04000000
      raw_string += 'CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL|'
    end
    if (flag & 0x08000000) == 0x08000000
      raw_string += 'CT_FLAG_SUBJECT_ALT_REQUIRE_DNS|'
    end
    if (flag & 0x10000000) == 0x10000000
      raw_string += 'CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN|'
    end
    if (flag & 0x20000000) == 0x20000000
      raw_string += 'CT_FLAG_SUBJECT_REQUIRE_EMAIL|'
    end
    if (flag & 0x40000000) == 0x40000000
      raw_string += 'CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME|'
    end
    if (flag & 0x80000000) == 0x80000000
      raw_string += 'CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH|'
    end
    raw_string.chomp!('|')

    raw_string
  end

  def find_acl_type_string(type)
    case type
    when 0x0
      'ACCESS_ALLOWED_ACE_TYPE'
    when 0x1
      'ACCESS_DENIED_ACE_TYPE'
    when 0x2
      'SYSTEM_AUDIT_ACE_TYPE'
    when 0x5
      'ACCESS_ALLOWED_OBJECT_ACE_TYPE'
    when 0x6
      'ACCESS_DENIED_OBJECT_ACE_TYPE'
    when 0x7
      'SYSTEM_AUDIT_OBJECT_ACE_TYPE'
    when 0x9
      'ACCESS_ALLOWED_CALLBACK_ACE_TYPE'
    when 0xA
      'ACCESS_DENIED_CALLBACK_ACE_TYPE'
    when 0xB
      'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE'
    when 0xC
      'ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE'
    when 0xD
      'SYSTEM_AUDIT_CALLBACK_ACE_TYPE'
    when 0xF
      'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE'
    when 0x11
      'SYSTEM_MANDATORY_LABEL_ACE_TYPE'
    when 0x12
      'SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE'
    when 0x13
      'SYSTEM_SCOPED_POLICY_ID_ACE_TYPE'
    else
      'RESERVED_OR_UNKNOWN_ACE_TYPE'
    end
  end

  def parse_access_mask(type, value)
    raw_string = ''
    case type
    when 0x11
      if (value & 0x00000001) == 0x00000001
        raw_string += 'SYSTEM_MANDATORY_LABEL_NO_WRITE_UP|'
      end
      if (value & 0x00000002) == 0x00000002
        raw_string += 'SYSTEM_MANDATORY_LABEL_NO_READ_UP|'
      end
      if (value & 0x00000004) == 0x00000004
        raw_string += 'SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP|'
      end
    end

    # Standard Rights
    if (value & 0x000F0000) == 0x000F0000
      raw_string += 'STANDARD_RIGHTS_REQUIRED|'
    else
      if (value & 0x00010000) == 0x00010000
        raw_string += 'DELETE|'
      end
      if (value & 0x00020000) == 0x00020000
        raw_string += 'READ_CONTROL|'
      end
      if (value & 0x00040000) == 0x00040000
        raw_string += 'WRITE_DAC|'
      end
      if (value & 0x00080000) == 0x00080000
        raw_string += 'WRITE_OWNER|'
      end
    end
    if (value & 0x00100000) == 0x00100000
      raw_string += 'SYNCHRONIZE|'
    end
    if (value & 0x001F0000) == 0x001F0000
      raw_string += 'STANDARD_RIGHTS_ALL|'
    end
    if (value & 0x0000FFFF) == 0x0000FFFF
      raw_string += 'SPECIFIC_RIGHTS_ALL|'
    end

    # Generic Access Codes
    if (value & 0x80000000) == 0x80000000
      raw_string += 'GENERIC_READ|'
    end
    if (value & 0x40000000) == 0x40000000
      raw_string += 'GENERIC_WRITE|'
    end
    if (value & 0x20000000) == 0x20000000
      raw_string += 'GENERIC_EXECUTE|'
    end
    if (value & 0x10000000) == 0x10000000
      raw_string += 'GENERIC_ALL|'
    end
    if (value & 0x2000000) == 0x2000000
      raw_string += 'MAXIMUM_ALLOWED|' # Should never be set normally though.
    end
    if (value & 0x1000000) == 0x1000000
      raw_string += 'ACCESS_SYSTEM_SECURITY|'
    end

    # MS-DTYP Specific Access Control Codes. Taken from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
    if (value & 0x001F01FF) == 0x001F01FF
      raw_string += 'FILE_ALL_ACCESS|'
    else
      if (value & 0x001200A0) == 0x001200A0
        raw_string += 'FILE_EXECUTE|'
      end
      if (value & 0x00120116) == 0x00120116
        raw_string += 'FILE_WRITE|'
      end
      if (value & 0x00120089) == 0x00120089
        raw_string += 'FILE_READ|'
      end
    end
    if (value & 0x000F003F) == 0x000F003F
      raw_string += 'KEY_ALL_ACCESS|'
    else
      if (value & 0x00020019) == 0x00020019
        raw_string += 'KEY_READ|KEY_EXECUTE|'
      end
      if (value & 0x00020006) == 0x00020006
        raw_string += 'KEY_WRITE|'
      end
    end
    if (value & 0x00000100) == 0x00000100
      raw_string += 'CONTROL_ACCESS|'
    end
    if (value & 0x00000080) == 0x00000080
      raw_string += 'LIST_OBJECT|'
    end
    if (value & 0x00000040) == 0x00000040
      raw_string += 'DELETE_TREE|'
    end
    if (value & 0x00000020) == 0x00000020
      raw_string += 'WRITE_PROPERTY|'
    end
    if (value & 0x00000010) == 0x00000010
      raw_string += 'READ_PROPERTY|'
    end
    if (value & 0x00000008) == 0x00000008
      raw_string += 'SELF_WRITE|'
    end
    if (value & 0x00000004) == 0x00000004
      raw_string += 'LIST_CHILDREN|'
    end
    if (value & 0x00000002) == 0x00000002
      raw_string += 'DELETE_CHILD|'
    end
    if (value & 0x00000001) == 0x00000001
      raw_string += 'CREATE_CHILD|'
    end

    raw_string.chomp('|')
  end

  def parse_dacl_or_sacl(acl)
    flag_allowed_to_enroll = nil
    allowed_sids = []
    acl.aces.each do |ace|
      ace_header = ace[:header]
      ace_body = ace[:body]
      if ace_body['access_mask'].blank? # This won't work with Symbols for some reason, but will work with strings. Bite me.
        fail_with(Failure::UnexpectedReply, 'Encountered a DACL/SACL object without an access mask! Either data is an unrecognized type or we are reading it wrong!')
      end
      ace_string = find_acl_type_string(ace_header[:ace_type])
      ace_access_mask = parse_access_mask(ace_header[:ace_type], ace_body[:access_mask])
      if ace_header[:ace_flags][:inherit_only_ace] == 1
        vprint_warning('      ACE only affects those that inherit from it, not those that it is attached to. Ignoring this ACE, as its not relevant.')
        next
      end

      # To decode the ObjectType we need to do another query to CN=Configuration,DC=daforest,DC=com
      # and look at either schemaIDGUID or rightsGUID fields to see if they match this value.
      next unless ace_body[:flags] && ace_body[:flags][:ace_object_type_present] == 1

      object_type = ace_body[:object_type]

      if ace_access_mask.match(/CONTROL_ACCESS/) && (object_type == CERTIFICATE_ENROLLMENT_EXTENDED_RIGHT || object_type == CERTIFICATE_AUTOENROLLMENT_EXTENDED_RIGHT)
        if ace_string.match(/DENIED/)
          flag_allowed_to_enroll = false
        elsif ace_string.match(/ALLOWED/)
          flag_allowed_to_enroll = true
          allowed_sids << ace_body[:sid].to_s
        end
      end
    end

    [flag_allowed_to_enroll, allowed_sids]
  end

  def query_ldap_server(raw_filter, attributes, base: nil, base_prefix: nil)
    ldap_connect do |ldap|
      full_base_dn, @base_dn = bind_to_server_and_get_dn(ldap: ldap, base: base, base_dn: @base_dn, base_prefix: base_prefix)

      if @base_dn.blank?
        fail_with(Failure::BadConfig, 'No base DN was found or specified, cannot continue!')
      elsif full_base_dn.blank?
        fail_with(Failure::BadConfig, 'Could not formulate the complete base DN!')
      end

      begin
        filter = Net::LDAP::Filter.construct(raw_filter)
      rescue StandardError => e
        fail_with(Failure::BadConfig, "Could not compile the filter to find the ESC1 objects! Error was #{e}")
      end

      returned_entries = ldap.search(base: full_base_dn, filter: filter, attributes: attributes)
      query_result = ldap.as_json['result']['ldap_result']

      result_code, result_message = check_query_result_code(query_result, filter)
      case result_code
      when -1
        fail_with(Failure::BadConfig, result_message)
      when 0
        vprint_good(result_message)
      when 1
        fail_with(Failure::NoAccess, result_message)
      when 2
        fail_with(Failure::UnexpectedReply, result_message)
      end

      if returned_entries.blank?
        print_error("No results found for #{filter}.")

        nil
      else

        returned_entries
      end
    end
  rescue Rex::ConnectionTimeout
    fail_with(Failure::Unreachable, "Couldn't reach #{datastore['RHOST']}!")
  rescue Net::LDAP::Error => e
    fail_with(Failure::UnexpectedReply, "Could not query #{datastore['RHOST']}! Error was: #{e.message}")
  end

  def run
    # Define our instance variables real quick.
    @base_dn = nil
    @vuln_cert_template_table = Rex::Text::Table.new(
      'Header' => 'Vulnerable Certificate Template List With Enrollment SIDs',
      'Indent' => 1,
      'Columns' => %w[ESC_VULN Template DN Enrollment_SIDS]
    )
    @enrollment_allowed_table = Rex::Text::Table.new(
      'Header' => 'Certificate Template Enrollment Allowed List By Server and SID',
      'Indent' => 1,
      'Columns' => %w[Server Template Enrollment_SIDS]
    )

    esc1_raw_filter = '(&'\
    '(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))'\
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
    attributes = ['cn', 'description', 'msPKI-Cert-Template-OID', 'msPKI-Certificate-Name-Flag', 'ntSecurityDescriptor']
    base_prefix = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration'
    entries = query_ldap_server(esc1_raw_filter, attributes, base_prefix: base_prefix)
    fail_with(Failure::NotVulnerable, 'Could not find any ESC1 vulnerable certificates!') if entries.blank?

    # Grab a list of certificates that contain vulnerable settings.
    # Also print out the list of SIDs that can enroll in that server.
    certificate_template_list = []
    entries.each do |entry|
      certificate_template_list << entry[:cn][0]

      begin
        security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(entry[:ntsecuritydescriptor][0])
      rescue IOError => e
        fail_with(Failure::UnexpectedReply, "Unable to read security descriptor! Error was: #{e.message}")
      end

      flag_allowed_to_enroll, allowed_sids = parse_dacl_or_sacl(security_descriptor.dacl) if security_descriptor.dacl
      if flag_allowed_to_enroll == true
        @vuln_cert_template_table << ['ESC1', entry[:cn][0], entry[:dn][0], allowed_sids.join(', ')]
      end
      parse_dacl_or_sacl(security_descriptor.sacl) if security_descriptor.sacl
    end

    print_line(@vuln_cert_template_table.to_s)

    # For each of the vulnerable certificate templates, determine which servers
    # allows users to enroll in that certificate template and which users/groups
    # have permissions to enroll in certificates on each server.

    certificate_template_list.each do |certificate_template|
      certificate_enrollment_raw_filter = "(&(objectClass=pKIEnrollmentService)(certificateTemplates=#{certificate_template}))"
      attributes = ['dnsHostname', 'ntsecuritydescriptor']
      base_prefix = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration'
      enrollment_ca_data = query_ldap_server(certificate_enrollment_raw_filter, attributes, base_prefix: base_prefix)
      next if enrollment_ca_data.blank?

      enrollment_ca_data.each do |ca_server|
        begin
          security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(ca_server[:ntsecuritydescriptor][0])
        rescue IOError => e
          fail_with(Failure::UnexpectedReply, "Unable to read security descriptor! Error was: #{e.message}")
        end

        flag_allowed_to_enroll, allowed_sids = parse_dacl_or_sacl(security_descriptor.dacl) if security_descriptor.dacl
        if flag_allowed_to_enroll == true
          @enrollment_allowed_table << [ca_server[:dnshostname][0], certificate_template, allowed_sids.join(', ')]
        end
        parse_dacl_or_sacl(security_descriptor.sacl) if security_descriptor.sacl
      end
    end

    print_line(@enrollment_allowed_table.to_s)
  end
end
