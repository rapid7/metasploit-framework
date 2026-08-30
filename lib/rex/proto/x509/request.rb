module Rex::Proto::X509

  # [2.2.2.7.7.4 szOID_NTDS_CA_SECURITY_EXT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71)
  OID_NTDS_CA_SECURITY_EXT = '1.3.6.1.4.1.311.25.2'.freeze
  # [2.2.2.7.5 szOID_NT_PRINCIPAL_NAME](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ea9ef420-4cbf-44bc-b093-c4175139f90f)
  OID_NT_PRINCIPAL_NAME = '1.3.6.1.4.1.311.20.2.3'.freeze
  # [[MS-WCCE]: Windows Client Certificate Enrollment Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-winerrata/c39fd72a-da21-4b13-b329-c35d61f74a60)
  OID_NTDS_OBJECTSID = '1.3.6.1.4.1.311.25.2.1'.freeze
  # [[MS-WCCE]: 2.2.2.7.10 szENROLLMENT_NAME_VALUE_PAIR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec)
  OID_ENROLLMENT_NAME_VALUE_PAIR = '1.3.6.1.4.1.311.13.2.1'.freeze
  # [[MS-WCCE]: 2.2.2.7.7.3 Encoding a Certificate Application Policy Extension](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/160b96b1-c431-457a-8eed-27c11873f378)
  OID_APPLICATION_CERT_POLICIES = '1.3.6.1.4.1.311.21.10'.freeze
  SAN_URL_PREFIX = "tag:microsoft.com,2022-09-14:sid:"

  class Request
    def self.create_csr(private_key, cn, algorithm = 'SHA256')
      request = OpenSSL::X509::Request.new
      request.subject = OpenSSL::X509::Name.new([
        ['CN', cn, OpenSSL::ASN1::UTF8STRING]
      ])
      request.public_key = private_key.public_key

      yield request if block_given?

      request.sign(private_key, OpenSSL::Digest.new(algorithm))
      request
    end
  # Make a certificate signing request.
  #
  # @param [String] cn The common name for the certificate.
  # @param [OpenSSL::PKey] private_key The private key for the certificate.
  # @param [String] dns An alternative DNS name to use.
  # @param [String] msext_sid An explicit SID to specify for strong identity mapping.
  # @param [String] msext_upn An alternative User Principal Name (this is a Microsoft-specific feature).
  # @param [String] algorithm The algorithm to use when signing the CSR.
  # @param [Array<String>] application_policies OIDs to add as application policies.
  # @return [OpenSSL::X509::Request] The request object.
  def self.build_csr(cn:, private_key:, dns: nil, msext_sid: nil, msext_upn: nil, algorithm: 'SHA256', application_policies: [])
    Rex::Proto::X509::Request.create_csr(private_key, cn, algorithm) do |request|
      extensions = []

      subject_alt_names = []
      subject_alt_names << "otherName = #{OID_NT_PRINCIPAL_NAME};UTF8:#{msext_upn}" if msext_upn

      if msext_sid
        subject_alt_names << "URI = #{SAN_URL_PREFIX}#{msext_sid}"
        subject_alt_names << "URI = #{msext_sid}"
      end

      subject_alt_names << "DNS = #{dns}" if dns

      unless subject_alt_names.empty?
        # factory.create_extension accepts a comma separated list of SANs or a config file of SANs.
        # SAN_URL_PREFIX in the URI SAN contains a comma so we create a config file and add it to the factory
        # The config file requires an identifier we define at the top of the file [alt_names]
        subject_alt_names.prepend("[alt_names]")
        subject_alt_names_conf = subject_alt_names.join("\n")
        config = OpenSSL::Config.parse(subject_alt_names_conf)
        factory = OpenSSL::X509::ExtensionFactory.new
        factory.config = config
        extensions << factory.create_extension('subjectAltName', '@alt_names', false)
      end

      if msext_sid
        ntds_ca_security_ext = Rex::Proto::CryptoAsn1::NtdsCaSecurityExt.new(OtherName: {
          type_id: OID_NTDS_OBJECTSID,
          value: msext_sid
        })
        extensions << OpenSSL::X509::Extension.new(OID_NTDS_CA_SECURITY_EXT, ntds_ca_security_ext.to_der, false)
      end

      unless application_policies.blank?
        application_cert_policies = Rex::Proto::CryptoAsn1::X509::CertificatePolicies.new(
          certificatePolicies: application_policies.map { |policy_oid| Rex::Proto::CryptoAsn1::X509::PolicyInformation.new(policyIdentifier: policy_oid) }
        )
        extensions << OpenSSL::X509::Extension.new(OID_APPLICATION_CERT_POLICIES, application_cert_policies.to_der, false)
      end

      unless extensions.empty?
        request.add_attribute(OpenSSL::X509::Attribute.new(
          'extReq',
          OpenSSL::ASN1::Set.new(
            [OpenSSL::ASN1::Sequence.new(extensions)]
          )
        ))
      end
    end
  end

  # Make a certificate request on behalf of another user.
  #
  # @param [OpenSSL::X509::Request] csr The certificate request to make on behalf of the user.
  # @param [String] on_behalf_of The user to make the request on behalf of.
  # @param [OpenSSL::X509::Certificate] cert The public key to use for signing the request.
  # @param [OpenSSL::PKey::RSA] key The private key to use for signing the request.
  # @param [String] algorithm The digest algorithm to use.
  # @return [Rex::Proto::CryptoAsn1::Cms::ContentInfo] The signed request content.
  def self.build_on_behalf_of(csr:, on_behalf_of:, cert:, key:, algorithm: 'SHA256')
    # algorithm needs to be one that OpenSSL supports, but we also need the OID constants defined
    digest = OpenSSL::Digest.new(algorithm)
    unless [ digest.name, "RSAWith#{digest.name}" ].all? { |s| Rex::Proto::Kerberos::Model::OID.constants.include?(s.to_sym) }
      raise ArgumentError, "Can not map digest algorithm #{digest.name} to the necessary OIDs."
    end

    digest_oid = Rex::Proto::Kerberos::Model::OID.const_get(digest.name)

    signer_info = Rex::Proto::CryptoAsn1::Cms::SignerInfo.new(
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

    signed_data = Rex::Proto::CryptoAsn1::Cms::SignedData.new(
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

    Rex::Proto::CryptoAsn1::Cms::ContentInfo.new(
      content_type: Rex::Proto::Kerberos::Model::OID::SignedData,
      data: signed_data
    )
  end

  end
end

