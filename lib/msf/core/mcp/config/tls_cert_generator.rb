# frozen_string_literal: true

require 'openssl'
require 'ipaddr'
require 'fileutils'

module Msf::MCP
  module Config
    #
    # Generates and caches a self-signed TLS certificate/key pair for the MCP
    # HTTP transport, used when the operator enables `mcp.ssl` without
    # supplying their own `ssl_cert` / `ssl_key`.
    #
    # This is a convenience default for local development and testing. It is
    # NOT a substitute for a certificate issued by a trusted CA (e.g. Let's
    # Encrypt) when the MCP server is reachable from another host -- clients
    # will need to explicitly trust the generated certificate, and it carries
    # none of the revocation/rotation guarantees a real CA provides.
    #
    # Unlike Msf::Ssl::CertProvider (lib/msf/core/cert_provider.rb), which
    # exists to generate randomized, evasive certificates for payload
    # handlers, this generator produces a plain, clearly-self-signed
    # certificate scoped to the host the server is bound to.
    #
    module TlsCertGenerator
      # Self-signed certs are cached here so restarts reuse the same
      # certificate instead of forcing clients to re-trust one every time.
      DEFAULT_CERT_DIRECTORY = File.join(Msf::Config.config_directory, 'mcp')
      DEFAULT_CERT_PATH = File.join(DEFAULT_CERT_DIRECTORY, 'server.crt')
      DEFAULT_KEY_PATH = File.join(DEFAULT_CERT_DIRECTORY, 'server.key')

      KEY_SIZE = 2048
      # 825 days is the longest lifetime modern browsers/clients will generally accept.
      VALIDITY_DAYS = 825
      # Regenerate a bit before actual expiry so a long-running install never serves an expired cert.
      RENEWAL_WINDOW_DAYS = 30

      # Return a valid, readable [cert_path, key_path] pair for the given host,
      # generating and caching a new self-signed certificate if none exists yet,
      # if it's expired/about to expire, or if it doesn't cover +host+.
      #
      # @param host [String] Host the MCP server will bind to; included in the certificate's SAN
      # @param cert_path [String] Where to read/write the certificate
      # @param key_path [String] Where to read/write the private key
      # @return [Array(String, String)] [cert_path, key_path]
      def self.ensure_self_signed_certificate(host: 'localhost', cert_path: DEFAULT_CERT_PATH, key_path: DEFAULT_KEY_PATH)
        if usable_certificate?(host, cert_path, key_path)
          return [cert_path, key_path]
        end

        key, cert = generate(host)
        write(cert, key, cert_path, key_path)
        [cert_path, key_path]
      end

      # @return [Boolean] true if a certificate/key already on disk at the given
      #   paths is valid, unexpired (outside the renewal window), and covers +host+
      def self.usable_certificate?(host, cert_path, key_path)
        return false unless File.file?(cert_path) && File.readable?(cert_path)
        return false unless File.file?(key_path) && File.readable?(key_path)

        cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
        OpenSSL::PKey::RSA.new(File.read(key_path))

        return false if cert.not_after < (Time.now + (RENEWAL_WINDOW_DAYS * 24 * 3600))
        return false unless san_covers_host?(cert, host)

        true
      rescue OpenSSL::X509::CertificateError, OpenSSL::PKey::RSAError, Errno::ENOENT, Errno::EACCES
        false
      end
      private_class_method :usable_certificate?

      # @return [Array(OpenSSL::PKey::RSA, OpenSSL::X509::Certificate)]
      def self.generate(host)
        key = OpenSSL::PKey::RSA.new(KEY_SIZE)

        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = OpenSSL::BN.rand(64, 0, false)
        cert.subject = OpenSSL::X509::Name.parse("/CN=#{host}/O=Metasploit MCP Server (self-signed)")
        cert.issuer = cert.subject
        cert.public_key = key.public_key
        cert.not_before = Time.now - 3600
        cert.not_after = Time.now + (VALIDITY_DAYS * 24 * 3600)

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = cert
        ef.issuer_certificate = cert
        cert.extensions = [
          ef.create_extension('basicConstraints', 'CA:FALSE', true),
          ef.create_extension('keyUsage', 'digitalSignature,keyEncipherment', true),
          ef.create_extension('extendedKeyUsage', 'serverAuth'),
          ef.create_extension('subjectKeyIdentifier', 'hash'),
          ef.create_extension('subjectAltName', sans_for(host))
        ]
        cert.sign(key, OpenSSL::Digest.new('SHA256'))

        [key, cert]
      end
      private_class_method :generate

      def self.write(cert, key, cert_path, key_path)
        FileUtils.mkdir_p(File.dirname(cert_path))
        FileUtils.mkdir_p(File.dirname(key_path))

        File.write(cert_path, cert.to_pem)
        File.write(key_path, key.to_pem)
        # Private key should only be readable by the owner.
        File.chmod(0o600, key_path)
      end
      private_class_method :write

      # Always include localhost/127.0.0.1 so local testing works regardless of
      # the configured bind host, plus the actual bind host/IP when it differs.
      def self.sans_for(host)
        entries = ['DNS:localhost', 'IP:127.0.0.1', 'IP:::1']
        extra = san_entry_for(host)
        entries << extra unless entries.include?(extra)
        entries.join(',')
      end
      private_class_method :sans_for

      def self.san_entry_for(host)
        ip?(host) ? "IP:#{host}" : "DNS:#{host}"
      end
      private_class_method :san_entry_for

      # @return [Boolean] true if +cert+'s subjectAltName covers +host+.
      #
      # OpenSSL renders SAN entries back as e.g. "DNS:localhost" or
      # "IP Address:127.0.0.1" (note: "IP Address", not "IP", and IPv6
      # addresses are rendered fully expanded) -- so entries are compared by
      # the value after the first colon, using IP-aware equality for IPs
      # rather than relying on an exact prefix match.
      def self.san_covers_host?(cert, host)
        ext = cert.extensions.find { |e| e.oid == 'subjectAltName' }
        return false unless ext

        values = ext.value.split(',').map { |entry| entry.strip.split(':', 2).last }
        host_ip = ip?(host) ? IPAddr.new(host) : nil

        values.any? do |value|
          if host_ip
            begin
              IPAddr.new(value) == host_ip
            rescue IPAddr::Error
              false
            end
          else
            value == host
          end
        end
      end
      private_class_method :san_covers_host?

      def self.ip?(host)
        IPAddr.new(host)
        true
      rescue IPAddr::Error
        false
      end
      private_class_method :ip?
    end
  end
end
