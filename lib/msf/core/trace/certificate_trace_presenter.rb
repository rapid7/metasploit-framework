# -*- coding: binary -*-

require 'openssl'

module Msf
  module Trace
    # Presenter for X.509 certificates (and optionally raw CSR data).
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
    #
    #   # CSR mode - expects raw DER/PEM CSR bytes, not a certificate:
    #   mod.print_line(presenter.to_s_csr(csr_raw))
    class CertificateTracePresenter

      SEPARATOR = ('[CertificateTrace] ' + ('-' * 38)).freeze

      # OIDs surfaced as named fields in to_s_full; excluded from the raw extension dump.
      NAMED_OIDS = %w[subjectAltName extendedKeyUsage keyUsage].freeze

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
        lines << "  Version    : #{@cert.version}"
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
          other.each { |e| lines << "    #{e.oid} : #{e.value}" }
        end

        lines.join("\n")
      end

      # Returns a formatted CSR string from raw CSR bytes.
      #
      # This method expects raw DER or PEM encoded CSR bytes - not a certificate
      # object. The 'csr' trace mode is intended for PKINIT pre-authentication
      # flows where the CSR is constructed and submitted separately from the
      # certificate. Callers must pass the CSR bytes directly rather than
      # converting from a certificate.
      #
      # Instance method - consistent with the presenter pattern.
      #
      # @param csr_raw [String] DER or PEM encoded certificate signing request
      # @return [String, nil] nil if CSR could not be parsed
      def to_s_csr(csr_raw)
        return nil unless csr_raw

        csr = OpenSSL::X509::Request.new(csr_raw)

        [
          SEPARATOR,
          "  CSR Subject : #{csr.subject}",
          "  CSR Pub Key : #{format_public_key(csr.public_key)}",
          "  CSR Sig Alg : #{csr.signature_algorithm}"
        ].join("\n")
      rescue OpenSSL::X509::RequestError
        nil
      end

      private

      def subject_cn
        @cert.subject.to_a.find { |name, _, _| name == 'CN' }&.dig(1)
      end

      def parse_san_identities
        san = @cert.extensions&.find { |e| e.oid == 'subjectAltName' }
        return {} unless san

        result = {}
        san.value.split(/,\s*/).each do |entry|
          case entry.strip
          when /\Aothername:\s*UPN:(.+)\z/i
            result[:upn] = ::Regexp.last_match(1).strip
          when /\Aemail:(.+)\z/i
            result[:email] = ::Regexp.last_match(1).strip
          end
        end
        result
      end

      def extension_value(oid)
        @cert.extensions&.find { |e| e.oid == oid }&.value
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
