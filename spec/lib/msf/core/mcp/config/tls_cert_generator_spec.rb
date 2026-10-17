# frozen_string_literal: true

require 'msf/core/mcp'
require 'tmpdir'

RSpec.describe Msf::MCP::Config::TlsCertGenerator do
  around do |example|
    Dir.mktmpdir('msf-mcp-tls-spec') do |dir|
      @cert_path = File.join(dir, 'server.crt')
      @key_path = File.join(dir, 'server.key')
      example.run
    end
  end

  describe '.ensure_self_signed_certificate' do
    it 'generates a certificate and key when none exist' do
      cert_path, key_path = described_class.ensure_self_signed_certificate(
        host: 'localhost', cert_path: @cert_path, key_path: @key_path
      )

      expect(File.file?(cert_path)).to be true
      expect(File.file?(key_path)).to be true

      cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
      key = OpenSSL::PKey::RSA.new(File.read(key_path))

      expect(cert.verify(key.public_key)).to be true
      expect(cert.not_after).to be > Time.now
    end

    it 'restricts the private key file permissions to the owner' do
      _, key_path = described_class.ensure_self_signed_certificate(
        host: 'localhost', cert_path: @cert_path, key_path: @key_path
      )

      mode = File.stat(key_path).mode & 0o777
      expect(mode).to eq(0o600)
    end

    it 'includes the given host in the certificate SAN' do
      cert_path, = described_class.ensure_self_signed_certificate(
        host: '192.168.1.50', cert_path: @cert_path, key_path: @key_path
      )
      cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
      san = cert.extensions.find { |e| e.oid == 'subjectAltName' }.value

      expect(san).to include('192.168.1.50')
    end

    it 'reuses an existing valid certificate rather than regenerating it' do
      described_class.ensure_self_signed_certificate(host: 'localhost', cert_path: @cert_path, key_path: @key_path)
      first_pem = File.read(@cert_path)

      described_class.ensure_self_signed_certificate(host: 'localhost', cert_path: @cert_path, key_path: @key_path)
      second_pem = File.read(@cert_path)

      expect(second_pem).to eq(first_pem)
    end

    it 'regenerates when the cached certificate does not cover the requested host' do
      described_class.ensure_self_signed_certificate(host: 'localhost', cert_path: @cert_path, key_path: @key_path)
      first_pem = File.read(@cert_path)

      described_class.ensure_self_signed_certificate(host: '10.0.0.5', cert_path: @cert_path, key_path: @key_path)
      second_pem = File.read(@cert_path)

      expect(second_pem).not_to eq(first_pem)
    end

    it 'regenerates when the cached certificate is expired' do
      described_class.ensure_self_signed_certificate(host: 'localhost', cert_path: @cert_path, key_path: @key_path)

      expired_cert = OpenSSL::X509::Certificate.new(File.read(@cert_path))
      expired_cert.not_after = Time.now - 3600
      key = OpenSSL::PKey::RSA.new(File.read(@key_path))
      expired_cert.sign(key, OpenSSL::Digest.new('SHA256'))
      File.write(@cert_path, expired_cert.to_pem)

      described_class.ensure_self_signed_certificate(host: 'localhost', cert_path: @cert_path, key_path: @key_path)
      regenerated = OpenSSL::X509::Certificate.new(File.read(@cert_path))

      expect(regenerated.not_after).to be > Time.now + (24 * 3600)
    end
  end
end
