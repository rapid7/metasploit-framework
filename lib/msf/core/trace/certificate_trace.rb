# -*- coding: binary -*-

require 'openssl'

module Msf
  module Trace
    # Provides inline certificate metadata inspection during module execution.
    # Modelled on the KerberosTicketTrace pattern — two explicit class methods
    # (print_metadata, print_full) dispatched by a certificate_trace() helper
    # in the including mixin, plus print_csr() for CSR-only inspection.
    #
    # Usage (from a module that includes the certificate_trace dispatcher):
    #
    #   set CertificateTrace metadata   # subject, issuer, serial
    #   set CertificateTrace full       # + validity dates + SHA-256 fingerprint
    #   set CertificateTrace csr        # CSR subject + version only
    #
    class CertificateTrace
      SEPARATOR = '[CertTrace] ' + ('-' * 43)

      # Coerces input to an OpenSSL::X509::Certificate.
      # Accepts either a live object or raw DER-encoded bytes.
      #
      # @param cert [OpenSSL::X509::Certificate, String] certificate or DER bytes
      # @return [OpenSSL::X509::Certificate]
      # @raise [OpenSSL::X509::CertificateError] if the input cannot be parsed
      def self.coerce(cert)
        cert.is_a?(OpenSSL::X509::Certificate) ? cert : OpenSSL::X509::Certificate.new(cert)
      end

      # Prints subject, issuer, and serial number.
      # Safe to call with raw DER bytes or a live certificate object.
      #
      # @param cert [OpenSSL::X509::Certificate, String]
      # @param mod  [#print_line] the calling module (used for output)
      def self.print_metadata(cert, mod)
        c = coerce(cert)
        mod.print_line(SEPARATOR)
        mod.print_line("  Subject : #{c.subject}")
        mod.print_line("  Issuer  : #{c.issuer}")
        mod.print_line("  Serial  : #{c.serial}")
      end

      # Prints all metadata fields plus validity window and SHA-256 fingerprint.
      # Calls print_metadata internally so all fields are always consistent.
      #
      # @param cert [OpenSSL::X509::Certificate, String]
      # @param mod  [#print_line] the calling module (used for output)
      def self.print_full(cert, mod)
        c = coerce(cert)
        print_metadata(c, mod)
        mod.print_line("  Valid From : #{c.not_before}")
        mod.print_line("  Valid To   : #{c.not_after}")
        fp = OpenSSL::Digest::SHA256.hexdigest(c.to_der)
        mod.print_line("  SHA-256    : #{fp}")
      end

      # Prints Certificate Signing Request subject and version.
      # Useful when inspecting ADCS certificate requests before issuance.
      #
      # @param csr_raw [String] DER-encoded CSR (OpenSSL::X509::Request)
      # @param mod     [#print_line] the calling module (used for output)
      # @raise [OpenSSL::X509::RequestError] if the input cannot be parsed
      def self.print_csr(csr_raw, mod)
        csr = OpenSSL::X509::Request.new(csr_raw)
        mod.print_line(SEPARATOR)
        mod.print_line("  CSR Subject : #{csr.subject}")
        mod.print_line("  CSR Version : #{csr.version}")
      end
    end
  end
end
