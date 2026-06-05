# -*- coding: binary -*-

require 'openssl'

module Msf
  module Trace
    # Presenter for X.509 certificates.
    #
    # Follows the same responsibility split as
    # Rex::Proto::Kerberos::CredentialCache::Krb5CCachePresenter:
    # this class constructs formatted strings only. The caller (module instance)
    # is responsible for invoking its own print methods so output is correctly
    # associated with the running module.
    #
    # Usage:
    #   presenter = Msf::Trace::CertificateTracePresenter.new(cert)
    #   mod.print_line(presenter.to_s_metadata)
    #   mod.print_line(presenter.to_s_full)
    class CertificateTracePresenter

      SEPARATOR = ('[CertificateTrace] ' + ('-' * 38)).freeze

      # OIDs surfaced as named fields in to_s_full; excluded from the raw extension dump.
      NAMED_OIDS = %w[subjectAltName extendedKeyUsage keyUsage].freeze

      # Microsoft AD CS enrollment extensions whose content carries the template
      # name / template version. OpenSSL has no friendly decoder for these, so we
      # decode them ourselves below.
      CERT_TEMPLATE_NAME_OID = '1.3.6.1.4.1.311.20.2'
      CERT_TEMPLATE_INFO_OID = '1.3.6.1.4.1.311.21.7'

      # Microsoft Application Policies extension. Its content is a
      # CertificatePolicies SEQUENCE OF PolicyInformation, which the framework
      # already decodes for the icpr_cert workflow; we resolve each policy OID to
      # its friendly label rather than dumping the raw bytes (the policy OIDs -
      # e.g. Client Authentication - are central to ESC attack triage).
      APPLICATION_POLICIES_OID = '1.3.6.1.4.1.311.21.10'

      # Friendly labels for extension OIDs that OpenSSL leaves as raw numeric
      # strings (predominantly Microsoft enrollment OIDs on AD CS certificates).
      EXTENSION_OID_NAMES = {
        CERT_TEMPLATE_NAME_OID => 'Certificate Template Name',
        CERT_TEMPLATE_INFO_OID => 'Certificate Template Information',
        APPLICATION_POLICIES_OID => 'Application Policies',
        '1.3.6.1.4.1.311.25.2' => 'AD DS Security Extension (SID)'
      }.freeze

      # Standard PKIX extensions OpenSSL renders as clean, human-readable text.
      # For any other extension - notably the Microsoft AD CS enrollment OIDs -
      # OpenSSL emits a lossy byte dump (raw bytes on OpenSSL, non-printables
      # collapsed to '.' on LibreSSL), so we hex-encode the raw extnValue
      # instead of printing mojibake. Matched against the short name OpenSSL
      # reports for recognised OIDs.
      OPENSSL_READABLE_EXTENSIONS = %w[
        basicConstraints
        authorityKeyIdentifier
        subjectKeyIdentifier
        crlDistributionPoints
        authorityInfoAccess
        certificatePolicies
        issuerAltName
        nameConstraints
        nsComment
        nsCertType
      ].freeze

      # Priority order for resolving a single auth identity from the cert.
      # UPN is the primary AD identity; email and CN are fallbacks.
      IDENTITY_SOURCES = [
        [:upn, 'UPN'],
        [:email, 'Email SAN'],
        [:cn, 'Subject CN']
      ].freeze

      # Attempt to coerce input into an OpenSSL::X509::Certificate.
      # Accepts a live certificate object, an OpenSSL::PKCS12 bundle (extracts
      # the leaf certificate), or raw DER/PEM bytes.
      #
      # @param cert [OpenSSL::X509::Certificate, OpenSSL::PKCS12, String]
      # @return [OpenSSL::X509::Certificate, nil]
      def self.coerce(cert)
        return cert if cert.is_a?(OpenSSL::X509::Certificate)
        return cert.certificate if cert.is_a?(OpenSSL::PKCS12)
        return OpenSSL::X509::Certificate.new(cert) if cert.is_a?(String)

        nil
      rescue OpenSSL::X509::CertificateError, OpenSSL::PKCS12::PKCS12Error
        nil
      end

      # @param cert [OpenSSL::X509::Certificate, OpenSSL::PKCS12, String]
      def initialize(cert)
        @cert = self.class.coerce(cert)
      end

      # Returns a formatted metadata string: subject, issuer, validity, SHA-256 fingerprint.
      #
      # @return [String, nil] nil if certificate could not be parsed
      def to_s_metadata
        return nil unless @cert

        fingerprint = OpenSSL::Digest::SHA256.hexdigest(@cert.to_der)

        [
          SEPARATOR,
          "  Subject    : #{@cert.subject}",
          "  Issuer     : #{@cert.issuer}",
          "  Not Before : #{@cert.not_before}",
          "  Not After  : #{@cert.not_after}",
          "  SHA-256    : #{fingerprint}"
        ].join("\n")
      end

      # Returns a formatted full string: metadata + serial, version, public key algorithm,
      # SAN / EKU / Key Usage as named fields, then remaining extensions.
      #
      # @return [String, nil] nil if certificate could not be parsed
      def to_s_full
        base = to_s_metadata
        return nil unless base

        lines = [base]
        lines << "  Serial     : #{@cert.serial}"
        # OpenSSL exposes the zero-based encoded X.509 version (v3 == 2).
        lines << "  Version    : v#{@cert.version + 1}"
        lines << "  Public Key : #{format_public_key(@cert.public_key)}"

        identities = parse_san_identities
        identity_key, identity_label = IDENTITY_SOURCES.find { |key, _| identities[key] }
        identity_value = identity_key ? identities[identity_key] : subject_cn
        identity_source = identity_key ? identity_label : 'Subject CN'
        lines << "  Identity   : #{identity_value} (#{identity_source})" if identity_value

        san = extension_value('subjectAltName')
        lines << "  SAN        : #{san}" if san

        eku = extension_value('extendedKeyUsage')
        lines << "  EKU        : #{eku}" if eku

        ku = extension_value('keyUsage')
        lines << "  Key Usage  : #{ku}" if ku

        other = @cert.extensions.reject { |e| NAMED_OIDS.include?(e.oid) }
        if other.any?
          lines << '  Extensions :'
          other.each do |e|
            label = EXTENSION_OID_NAMES[normalize_oid(e.oid)] || e.oid
            lines << "    #{label} : #{format_extension(e)}"
          end
        end

        lines.join("\n")
      end

      private

      def subject_cn
        @cert.subject.to_a.find { |name, _, _| name == 'CN' }&.dig(1)
      end

      # Resolve auth identities (UPN, email) from the certificate's subjectAltName.
      #
      # AD-issued certificates encode the UPN as an otherName GeneralName, which
      # OpenSSL does not format reliably as a string across versions. Decode the
      # extension as ASN.1 instead, mirroring the PKINIT SAN handling in
      # Msf::Exploit::Remote::Kerberos::Client::Pkinit#extract_user_and_realm.
      #
      # @return [Hash{Symbol => String}] identity values keyed by :upn / :email
      def parse_san_identities
        result = {}
        return result unless @cert&.extensions

        @cert.extensions.select { |ext| ext.oid == 'subjectAltName' }.each do |san_extension|
          asn_san = OpenSSL::ASN1.decode(san_extension)
          octet_string = asn_san.value.find { |value| value.is_a?(OpenSSL::ASN1::OctetString) }
          next unless octet_string

          OpenSSL::ASN1.decode(octet_string.value).value.each do |san_entry|
            case san_entry.tag
            when 0 # otherName - AD stores the UPN principal name here
              next unless san_entry.value[0]&.value == 'msUPN'

              result[:upn] ||= san_entry.value[1].value[0].value
            when 1 # rfc822Name (email)
              result[:email] ||= san_entry.value
            end
          end
        rescue StandardError
          next
        end

        result
      end

      def extension_value(oid)
        @cert.extensions&.find { |e| e.oid == oid }&.value
      end

      # Render an extension value as human-readable text.
      #
      # OpenSSL formats the standard PKIX extensions (subjectKeyIdentifier,
      # crlDistributionPoints, etc.) well, but for OIDs it cannot decode -
      # notably the Microsoft AD CS enrollment extensions - Extension#value
      # returns a lossy byte dump that surfaces as mojibake such as "...U.s.e.r".
      # Decode the MS template extensions we recognise; defer to OpenSSL for the
      # standard extensions it renders cleanly; hex-encode everything else so the
      # raw bytes stay unambiguous and copy-pasteable.
      #
      # @param ext [OpenSSL::X509::Extension]
      # @return [String]
      def format_extension(ext)
        case normalize_oid(ext.oid)
        when CERT_TEMPLATE_NAME_OID
          asn1 = inner_extension_asn1(ext)
          return clean_text(asn1.value) if asn1
        when CERT_TEMPLATE_INFO_OID
          decoded = format_template_information(ext)
          return decoded if decoded
        when APPLICATION_POLICIES_OID
          decoded = format_application_policies(ext)
          return decoded if decoded
        end

        return ext.value if OPENSSL_READABLE_EXTENSIONS.include?(ext.oid)

        hex_encode(raw_extension_bytes(ext) || ext.value)
      rescue StandardError
        hex_encode(raw_extension_bytes(ext) || ext.value)
      end

      # Resolve an extension OID to its dotted numeric form. OpenSSL may surface
      # a registered short name (e.g. "ms-cert-templ") rather than the numeric
      # OID depending on its object table / OPENSSL_CONF, so normalise before
      # matching.
      #
      # @param oid [String]
      # @return [String]
      def normalize_oid(oid)
        OpenSSL::ASN1::ObjectId.new(oid).oid
      rescue OpenSSL::ASN1::ASN1Error
        oid
      end

      # Decode the DER content carried inside an extension. Extension#to_der wraps
      # the value in an OCTET STRING; return the parsed ASN.1 of that inner content.
      #
      # @param ext [OpenSSL::X509::Extension]
      # @return [OpenSSL::ASN1::ASN1Data, nil]
      def inner_extension_asn1(ext)
        seq = OpenSSL::ASN1.decode(ext.to_der)
        octet = seq.value.find { |v| v.is_a?(OpenSSL::ASN1::OctetString) }
        return nil unless octet

        OpenSSL::ASN1.decode(octet.value)
      rescue OpenSSL::ASN1::ASN1Error
        nil
      end

      # Format the Microsoft Certificate Template Information extension:
      # SEQUENCE { templateID OID, majorVersion INTEGER, minorVersion INTEGER OPTIONAL }.
      #
      # @param ext [OpenSSL::X509::Extension]
      # @return [String, nil] nil if the extension could not be decoded
      def format_template_information(ext)
        asn1 = inner_extension_asn1(ext)
        return nil unless asn1.respond_to?(:value) && asn1.value.is_a?(Array)

        oid, major, minor = asn1.value.map { |v| v&.value }
        out = "Template #{oid}"
        out += " (v#{major}#{minor ? ".#{minor}" : ''})" if major
        out
      end

      # Decode the Microsoft Application Policies extension to its policy OIDs and
      # friendly labels. The extnValue is a CertificatePolicies structure; reuse
      # the framework's parser and OID table so the output matches what the
      # icpr_cert module already prints (Msf::Exploit::Remote::CertRequest).
      #
      # @param ext [OpenSSL::X509::Extension]
      # @return [String, nil] e.g. "1.3.6.1.5.5.7.3.2 (Client Authentication)", nil if undecodable
      def format_application_policies(ext)
        policies = Rex::Proto::CryptoAsn1::X509::CertificatePolicies.parse(ext.value_der)
        labels = policies.value.map do |policy_info|
          oid_string = policy_info[:policyIdentifier].value
          oid = Rex::Proto::CryptoAsn1::OIDs.value(oid_string)
          oid&.label.to_s.empty? ? oid_string : "#{oid_string} (#{oid.label})"
        end
        return nil if labels.empty?

        labels.join(', ')
      rescue StandardError
        nil
      end

      # Extract the raw extnValue octets carried inside an extension. Extension#to_der
      # wraps the value in an OCTET STRING; return those inner bytes so they can be
      # hex-encoded rather than dumped through OpenSSL's lossy string rendering.
      #
      # @param ext [OpenSSL::X509::Extension]
      # @return [String, nil]
      def raw_extension_bytes(ext)
        seq = OpenSSL::ASN1.decode(ext.to_der)
        seq.value.find { |v| v.is_a?(OpenSSL::ASN1::OctetString) }&.value
      rescue OpenSSL::ASN1::ASN1Error
        nil
      end

      # @param str [String]
      # @return [String] uppercase colon-separated hex (e.g. "30:0C:06:0A")
      def hex_encode(str)
        str.to_s.b.unpack1('H*').upcase.scan(/../).join(':')
      end

      # Normalise a decoded ASN.1 string value to clean UTF-8. BMPString content
      # arrives as UTF-16, so re-encode and strip embedded NUL bytes.
      #
      # @param str [String]
      # @return [String]
      def clean_text(str)
        s = str.to_s
        s = s.encode('UTF-8', 'UTF-16BE') if s.encoding == ::Encoding::UTF_16BE
        s = s.b.force_encoding('UTF-8')
        s = s.scrub('?') unless s.valid_encoding?
        s.delete("\u0000")
      end

      def format_public_key(pk)
        case pk
        when OpenSSL::PKey::RSA
          "RSA-#{pk.n.num_bits}"
        when OpenSSL::PKey::EC
          "EC-#{pk.group.degree}"
        when OpenSSL::PKey::DSA
          "DSA-#{pk.p.num_bits}"
        else
          pk.class.name.split('::').last
        end
      rescue StandardError
        'unknown'
      end
    end
  end
end
