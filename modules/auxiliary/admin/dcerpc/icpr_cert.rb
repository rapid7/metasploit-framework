##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report

  NTDS_CA_SECURITY_EXT = '1.3.6.1.4.1.311.25.2'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ICPR Cert Management',
        'Description' => %q{
        },
        'License' => MSF_LICENSE,
        'Author' => [
          # todo: Original certipy code
          'Spencer McIntyre',
        ],
        'References' => [
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Actions' => [
          [ 'REQUEST_CERT', { 'Description' => 'Request a certificate' } ]
        ],
        'DefaultAction' => 'REQUEST_CERT'
      )
    )

    register_options([
      Opt::RPORT(445)
    ])
  end

  def connect_icpr
    vprint_status('Connecting to ICertPassage (ICPR) Remote Protocol')
    #icpr = @tree.open_file(filename: 'cert', write: true, read: true)
    icpr = RubySMB::Dcerpc::Client.new(
      rhost,
      RubySMB::Dcerpc::Icpr,
      username: datastore['SMBUser'],
      password: datastore['SMBPass']
    )
    icpr.connect

    vprint_status('Binding to \\cert...')
    icpr.bind(
      endpoint: RubySMB::Dcerpc::Icpr,
      auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
      auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
    )
    vprint_good('Bound to \\cert')

    icpr
  end

  def run
    # begin
    #   connect
    # rescue Rex::ConnectionError => e
    #   fail_with(Failure::Unreachable, e.message)
    # end
    #
    # begin
    #   smb_login
    # rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
    #   fail_with(Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
    # end
    # report_service(
    #   host: rhost,
    #   port: rport,
    #   host_name: simple.client.default_name,
    #   proto: 'tcp',
    #   name: 'smb',
    #   info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    # )
    #
    # begin
    #   @tree = simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    # rescue RubySMB::Error::RubySMBError => e
    #   fail_with(Failure::Unreachable, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    # end

    begin
      @icpr = connect_icpr
    rescue RubySMB::Error::UnexpectedStatusCode => e
      if e.status_code == ::WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND
        # STATUS_OBJECT_NAME_NOT_FOUND will be the status if Active Directory Certificate Service (AD CS) is not installed on the target
        fail_with(Failure::NotFound, 'Connection failed (AD CS was not found)')
      end

      elog(e.message, error: e)
      fail_with(Failure::UnexpectedReply, "Connection failed (unexpected status: #{e.status_name})")
    end

    send("action_#{action.name.downcase}")
  rescue RubySMB::Dcerpc::Error::FaultError => e
    elog(e.message, error: e)
    fail_with(Failure::UnexpectedReply, "Operation failed (DCERPC fault: #{e.status_name})")
  rescue RubySMB::Dcerpc::Error::DcerpcError => e
    elog(e.message, error: e)
    fail_with(Failure::UnexpectedReply, e.message)
  rescue RubySMB::Error::RubySMBError
    elog(e.message, error: e)
    fail_with(Failure::Unknown, e.message)
  end

  def action_request_cert
    private_key = OpenSSL::PKey::RSA.new(2048)
    csr = make_csr(cn: 'smcintyre', private_key: private_key)

    print_status('Requesting a certificate...')
    response = @icpr.cert_server_request(
      attributes: { 'CertificateTemplate' => 'User' },
      authority: 'msflab-DC-CA',
      csr: csr
    )
    case response[:status]
    when :issued
      print_good('The requested certificate was issued.')
    when :submitted
      print_warning('The requested certificate was submitted for review.')
    else
      print_error('There was an error while requesting the certificate.')
      return
    end

    if (upn = get_cert_upn(response[:certificate]))
      print_status("Certificate UPN: #{upn}")
    end

    if (sid = get_cert_sid(response[:certificate]))
      print_status("Certificate SID: #{sid}")
    end

    pkcs12 = OpenSSL::PKCS12.create(
      '',
      '',
      private_key,
      response[:certificate]
    )
    # see: https://pki-tutorial.readthedocs.io/en/latest/mime.html#mime-types
    stored_path = store_loot('certificate.pfx', 'application/x-pkcs12', nil, pkcs12.to_der, 'certificate.pfx', 'Certificate')
    print_status("Certificate stored at: #{stored_path}")
  end

  def make_csr(cn:, private_key:)
    request = OpenSSL::X509::Request.new
    request.version = 1
    request.subject = OpenSSL::X509::Name.new([
      ['CN', cn,  OpenSSL::ASN1::UTF8STRING]
    ])
    request.public_key = private_key.public_key
    request.sign(private_key, OpenSSL::Digest::SHA256.new)
    request
  end

  def get_cert_sid(cert)
    ext = cert.find_extension(NTDS_CA_SECURITY_EXT)
    return unless ext

    ext_asn = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(ext.to_der).value[1].value)
    ext_asn.value.each do |value|
      value = value.value
      next unless value.is_a?(Array)
      next unless value[0].value == '1.3.6.1.4.1.311.25.2.1'

      return value[1].value[0].value
    end

    nil
  end

  def get_cert_upn(cert)
    ext = cert.find_extension('subjectAltName')
    return unless ext

    # need to decode the contents and handle them ourselves
    ext_asn = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(ext.to_der).value[1].value)
    ext_asn.value.each do |value|
      value = value.value
      next unless value.is_a?(Array)
      next unless value[0].value == 'msUPN'

      return value[1].value[0].value
    end

    nil
  end
end
