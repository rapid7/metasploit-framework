# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'msf/core/trace/certificate_trace_presenter'

RSpec.describe Msf::Trace::CertificateTracePresenter do
  # ── Shared cert fixture ──────────────────────────────────────────────────────

  let(:key) { OpenSSL::PKey::RSA.generate(2048) }

  let(:cert) do
    c            = OpenSSL::X509::Certificate.new
    c.subject    = OpenSSL::X509::Name.parse('/CN=Administrator/DC=CONTOSO/DC=LOCAL')
    c.issuer     = OpenSSL::X509::Name.parse('/CN=CONTOSO-CA/DC=CONTOSO/DC=LOCAL')
    c.public_key = key.public_key
    c.serial     = OpenSSL::BN.new('12345')
    c.version    = 2
    c.not_before = Time.utc(2026, 1, 1)
    c.not_after  = Time.utc(2027, 1, 1)
    c.sign(key, OpenSSL::Digest::SHA256.new)
    c
  end

  # Certificate with SAN, EKU, and Key Usage extensions — mirrors a real ADCS-issued cert.
  let(:cert_with_extensions) do
    c            = OpenSSL::X509::Certificate.new
    c.subject    = OpenSSL::X509::Name.parse('/CN=Administrator/DC=CONTOSO/DC=LOCAL')
    c.issuer     = OpenSSL::X509::Name.parse('/CN=CONTOSO-CA/DC=CONTOSO/DC=LOCAL')
    c.public_key = key.public_key
    c.serial     = OpenSSL::BN.new('99999')
    c.version    = 2
    c.not_before = Time.utc(2026, 1, 1)
    c.not_after  = Time.utc(2027, 1, 1)

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = c
    ef.issuer_certificate  = c
    c.add_extension(ef.create_extension('subjectAltName', 'email:admin@contoso.local'))
    c.add_extension(ef.create_extension('extendedKeyUsage', 'clientAuth'))
    c.add_extension(ef.create_extension('keyUsage', 'digitalSignature', true))
    c.sign(key, OpenSSL::Digest::SHA256.new)
    c
  end

  let(:pfx) { OpenSSL::PKCS12.create('', 'Administrator', key, cert) }

  let(:presenter) { described_class.new(cert) }

  # ── .coerce ──────────────────────────────────────────────────────────────────
  describe '.coerce' do
    it 'passes through an existing OpenSSL::X509::Certificate unchanged' do
      expect(described_class.coerce(cert)).to equal(cert)
    end

    it 'coerces DER bytes to an OpenSSL::X509::Certificate' do
      result = described_class.coerce(cert.to_der)
      expect(result).to be_a(OpenSSL::X509::Certificate)
    end

    it 'returns nil for invalid input' do
      expect(described_class.coerce('not a cert')).to be_nil
    end

    it 'extracts the leaf certificate from an OpenSSL::PKCS12 bundle' do
      result = described_class.coerce(pfx)
      expect(result).to be_a(OpenSSL::X509::Certificate)
    end

    it 'initializes correctly from a PKCS12 bundle' do
      expect(described_class.new(pfx).to_s_metadata).to include('Administrator')
    end
  end

  # ── #to_s_metadata ──────────────────────────────────────────────────────────
  describe '#to_s_metadata' do
    subject { presenter.to_s_metadata }

    it 'returns a string' do
      expect(subject).to be_a(String)
    end

    it 'includes the separator' do
      expect(subject).to include('[CertificateTrace]')
    end

    it 'includes subject' do
      expect(subject).to include('Administrator')
    end

    it 'includes issuer' do
      expect(subject).to include('CONTOSO-CA')
    end

    it 'includes validity window labels' do
      expect(subject).to include('Not Before')
      expect(subject).to include('Not After')
    end

    it 'includes SHA-256 label' do
      expect(subject).to include('SHA-256')
    end

    it 'SHA-256 value matches OpenSSL::Digest::SHA256.hexdigest' do
      expected = OpenSSL::Digest::SHA256.hexdigest(cert.to_der)
      expect(subject).to include(expected)
    end

    it 'returns nil when certificate cannot be parsed' do
      expect(described_class.new('garbage').to_s_metadata).to be_nil
    end

    it 'accepts DER bytes without raising' do
      expect { described_class.new(cert.to_der).to_s_metadata }.not_to raise_error
    end
  end

  # ── #to_s_full ───────────────────────────────────────────────────────────────
  describe '#to_s_full' do
    subject { presenter.to_s_full }

    it 'includes everything from metadata' do
      expect(subject).to include('Administrator')
      expect(subject).to include('SHA-256')
    end

    it 'includes serial number' do
      expect(subject).to include('Serial')
      expect(subject).to include('12345')
    end

    it 'includes the certificate version as a one-based value' do
      expect(subject).to include('Version')
      # OpenSSL encodes a v3 certificate as version 2; users expect "v3".
      expect(subject).to include('v3')
    end

    it 'includes public key as algorithm and bit size, not raw PEM' do
      expect(subject).to include('RSA-2048')
      expect(subject).not_to include('-----BEGIN')
    end

    it 'returns nil when certificate cannot be parsed' do
      expect(described_class.new('garbage').to_s_full).to be_nil
    end

    it 'accepts DER bytes without raising' do
      expect { described_class.new(cert.to_der).to_s_full }.not_to raise_error
    end

    it 'does not crash when certificate has no extensions' do
      expect { described_class.new(cert).to_s_full }.not_to raise_error
    end
  end

  # ── #to_s_full with SAN / EKU / Key Usage ────────────────────────────────────
  describe '#to_s_full with authentication-relevant extensions' do
    subject { described_class.new(cert_with_extensions).to_s_full }

    it 'includes SAN as a named field' do
      expect(subject).to include('SAN')
    end

    it 'includes the SAN value' do
      expect(subject).to include('admin@contoso.local')
    end

    it 'includes EKU as a named field' do
      expect(subject).to include('EKU')
    end

    it 'includes Key Usage as a named field' do
      expect(subject).to include('Key Usage')
    end

    it 'does not dump SAN inside the raw Extensions block' do
      lines = subject.lines
      ext_block_start = lines.index { |l| l.include?('Extensions :') }
      if ext_block_start
        ext_lines = lines[(ext_block_start + 1)..].take_while { |l| l.start_with?('    ') }
        san_in_raw = ext_lines.any? { |l| l.include?('subjectAltName') }
        expect(san_in_raw).to be false
      end
    end
  end

  # ── identity mapping ────────────────────────────────────────────────────────

  describe '#to_s_full identity mapping' do
    let(:cert_with_upn) do
      c            = OpenSSL::X509::Certificate.new
      c.subject    = OpenSSL::X509::Name.parse('/CN=Administrator/DC=CONTOSO/DC=LOCAL')
      c.issuer     = OpenSSL::X509::Name.parse('/CN=CONTOSO-CA/DC=CONTOSO/DC=LOCAL')
      c.public_key = key.public_key
      c.serial     = OpenSSL::BN.new('1')
      c.version    = 2
      c.not_before = Time.utc(2026, 1, 1)
      c.not_after  = Time.utc(2027, 1, 1)

      san_conf = ["[alt_names]", "otherName = 1.3.6.1.4.1.311.20.2.3;UTF8:admin@CONTOSO.LOCAL"]
      config = OpenSSL::Config.parse(san_conf.join("\n"))
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.config = config
      c.add_extension(factory.create_extension('subjectAltName', '@alt_names', false))
      c.sign(key, OpenSSL::Digest::SHA256.new)
      c
    end

    let(:cert_with_email_san) do
      c            = OpenSSL::X509::Certificate.new
      c.subject    = OpenSSL::X509::Name.parse('/CN=Alice/DC=CONTOSO/DC=LOCAL')
      c.issuer     = OpenSSL::X509::Name.parse('/CN=CONTOSO-CA/DC=CONTOSO/DC=LOCAL')
      c.public_key = key.public_key
      c.serial     = OpenSSL::BN.new('2')
      c.version    = 2
      c.not_before = Time.utc(2026, 1, 1)
      c.not_after  = Time.utc(2027, 1, 1)

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = c
      ef.issuer_certificate  = c
      c.add_extension(ef.create_extension('subjectAltName', 'email:alice@contoso.local'))
      c.sign(key, OpenSSL::Digest::SHA256.new)
      c
    end

    context 'when cert has a UPN SAN' do
      subject { described_class.new(cert_with_upn).to_s_full }

      it 'includes Identity label' do
        expect(subject).to include('Identity')
      end

      it 'shows the UPN value' do
        expect(subject).to include('admin@CONTOSO.LOCAL')
      end

      it 'labels the source as UPN' do
        expect(subject).to include('UPN')
      end
    end

    context 'when cert has an email SAN but no UPN' do
      subject { described_class.new(cert_with_email_san).to_s_full }

      it 'shows the email identity' do
        expect(subject).to include('alice@contoso.local')
      end

      it 'labels the source as Email SAN' do
        expect(subject).to include('Email SAN')
      end
    end

    context 'when cert has no SAN' do
      subject { described_class.new(cert).to_s_full }

      it 'falls back to Subject CN' do
        expect(subject).to include('Administrator')
      end

      it 'labels the source as Subject CN' do
        expect(subject).to include('Subject CN')
      end
    end
  end

  # ── #to_s_full extension value decoding (Microsoft AD CS OIDs) ───────────────
  describe '#to_s_full extension value decoding' do
    # Build a self-signed cert carrying a single raw extension whose extnValue
    # OCTET STRING wraps the supplied bytes.
    def cert_with_raw_extension(oid, content)
      c            = OpenSSL::X509::Certificate.new
      c.subject    = OpenSSL::X509::Name.parse('/CN=Administrator/DC=CONTOSO/DC=LOCAL')
      c.issuer     = OpenSSL::X509::Name.parse('/CN=CONTOSO-CA/DC=CONTOSO/DC=LOCAL')
      c.public_key = key.public_key
      c.serial     = OpenSSL::BN.new('7')
      c.version    = 2
      c.not_before = Time.utc(2026, 1, 1)
      c.not_after  = Time.utc(2027, 1, 1)

      ext_der = OpenSSL::ASN1::Sequence.new(
        [
          OpenSSL::ASN1::ObjectId.new(oid),
          OpenSSL::ASN1::OctetString.new(content)
        ]
      ).to_der
      c.add_extension(OpenSSL::X509::Extension.new(ext_der))
      c.sign(key, OpenSSL::Digest::SHA256.new)
      c
    end

    context 'with a Microsoft Certificate Template Name extension (BMPString)' do
      subject do
        content = OpenSSL::ASN1::BMPString.new('User'.encode('UTF-16BE').b).to_der
        described_class.new(cert_with_raw_extension('1.3.6.1.4.1.311.20.2', content)).to_s_full
      end

      it 'labels the OID with a friendly name' do
        expect(subject).to include('Certificate Template Name')
      end

      it 'decodes the BMPString value to readable text' do
        expect(subject).to include('User')
      end

      it 'does not emit NUL bytes from the UTF-16 encoding' do
        expect(subject).not_to include("\u0000")
      end
    end

    context 'with a Microsoft Certificate Template Information extension' do
      subject do
        content = OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::ObjectId.new('1.3.6.1.4.1.311.21.8.1.2.3'),
            OpenSSL::ASN1::Integer.new(100),
            OpenSSL::ASN1::Integer.new(5)
          ]
        ).to_der
        described_class.new(cert_with_raw_extension('1.3.6.1.4.1.311.21.7', content)).to_s_full
      end

      it 'labels the OID with a friendly name' do
        expect(subject).to include('Certificate Template Information')
      end

      it 'renders the template OID and version' do
        expect(subject).to include('Template 1.3.6.1.4.1.311.21.8.1.2.3')
        expect(subject).to include('v100.5')
      end
    end

    context 'with an unrecognized binary extension' do
      subject do
        described_class.new(cert_with_raw_extension('1.3.6.1.4.1.99999.1', "\x00\x01\x02\xFF".b)).to_s_full
      end

      it 'renders without raising and labels it by OID' do
        expect(subject).to be_a(String)
        expect(subject).to include('1.3.6.1.4.1.99999.1')
      end

      it 'hex-encodes the raw bytes instead of emitting mojibake' do
        expect(subject).to include('00:01:02:FF')
      end

      it 'does not emit non-printable bytes in the extensions block' do
        ext_lines = subject.lines.select { |l| l.start_with?('    ') }.join
        expect(ext_lines).not_to match(/[^[:print:]\t]/)
      end
    end

    context 'with a Microsoft Application Policies extension' do
      # Application Policies (1.3.6.1.4.1.311.21.10) wraps a CertificatePolicies
      # SEQUENCE OF PolicyInformation. OpenSSL knows the OID name but renders the
      # structured content as a lossy byte dump, so the presenter decodes the
      # policy OIDs and resolves them to friendly labels.
      subject do
        content = OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('1.3.6.1.5.5.7.3.2')]),
            OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('1.3.6.1.5.5.7.3.1')])
          ]
        ).to_der
        described_class.new(cert_with_raw_extension('1.3.6.1.4.1.311.21.10', content)).to_s_full
      end

      it 'labels the OID with a friendly name' do
        expect(subject).to include('Application Policies')
      end

      it 'decodes each policy OID to its dotted value and label' do
        expect(subject).to include('1.3.6.1.5.5.7.3.2 (Client Authentication)')
        expect(subject).to include('1.3.6.1.5.5.7.3.1 (Server Authentication)')
      end

      it 'does not hex-encode the structured content' do
        expect(subject).not_to include('30:0')
      end

      it 'does not emit non-printable bytes in the extensions block' do
        ext_lines = subject.lines.select { |l| l.start_with?('    ') }.join
        expect(ext_lines).not_to match(/[^[:print:]\t]/)
      end
    end

    context 'with an Application Policies OID that has no friendly label' do
      # OID_ANY_APPLICATION_POLICY is in the framework's OID table but carries no
      # label; it should still print as its dotted value, never a hex dump.
      subject do
        content = OpenSSL::ASN1::Sequence.new(
          [OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('1.3.6.1.4.1.311.10.12.1')])]
        ).to_der
        described_class.new(cert_with_raw_extension('1.3.6.1.4.1.311.21.10', content)).to_s_full
      end

      it 'prints the bare OID with no label parenthetical' do
        expect(subject).to match(/Application Policies : 1\.3\.6\.1\.4\.1\.311\.10\.12\.1(\s|$)/)
      end
    end
  end

  # ── CSR presentation ─────────────────────────────────────────────────────────
  # A real certificate signing request built through the same helper the
  # MS-ICPR / AD CS enrollment flow uses (Rex::Proto::X509::Request.build_csr),
  # carrying a UPN SAN and an application-policy (EKU) extension.
  describe 'CSR presentation' do
    let(:csr) do
      Rex::Proto::X509::Request.build_csr(
        cn: 'Administrator',
        private_key: key,
        dns: 'dc.contoso.local',
        msext_upn: 'administrator@contoso.local',
        algorithm: 'SHA256',
        application_policies: ['1.3.6.1.5.5.7.3.2']
      )
    end

    let(:attributes) do
      { 'CertificateTemplate' => 'User', 'SAN' => 'dns=dc.contoso.local&upn=administrator@contoso.local' }
    end

    describe '.coerce_csr' do
      it 'passes through an existing OpenSSL::X509::Request unchanged' do
        expect(described_class.coerce_csr(csr)).to equal(csr)
      end

      it 'coerces DER bytes to an OpenSSL::X509::Request' do
        expect(described_class.coerce_csr(csr.to_der)).to be_a(OpenSSL::X509::Request)
      end

      it 'returns nil for invalid input' do
        expect(described_class.coerce_csr('not a csr')).to be_nil
      end

      it 'returns nil for an unrelated object' do
        expect(described_class.coerce_csr(Object.new)).to be_nil
      end
    end

    describe '#to_s_csr_metadata' do
      subject { described_class.new.to_s_csr_metadata(csr) }

      it 'includes the CertificateTrace separator' do
        expect(subject).to include('[CertificateTrace]')
      end

      it 'includes the CSR subject' do
        expect(subject).to include('CSR Subject')
        expect(subject).to include('Administrator')
      end

      it 'renders the public key as algorithm and bit size, not raw PEM' do
        expect(subject).to include('CSR Pub Key')
        expect(subject).to include('RSA-2048')
        expect(subject).not_to include('-----BEGIN')
      end

      it 'includes the signature algorithm' do
        expect(subject).to include('CSR Sig Alg')
      end

      it 'accepts DER bytes without raising' do
        expect { described_class.new.to_s_csr_metadata(csr.to_der) }.not_to raise_error
      end

      it 'returns nil when the CSR cannot be parsed' do
        expect(described_class.new.to_s_csr_metadata('garbage')).to be_nil
      end

      it 'returns nil for a nil CSR' do
        expect(described_class.new.to_s_csr_metadata(nil)).to be_nil
      end
    end

    describe '#to_s_csr_full' do
      subject { described_class.new.to_s_csr_full(csr, attributes) }

      it 'includes everything from metadata' do
        expect(subject).to include('CSR Subject')
        expect(subject).to include('RSA-2048')
      end

      it 'includes the requested certificate template from attributes' do
        expect(subject).to include('Req Template')
        expect(subject).to include('User')
      end

      it 'includes the requested SAN from attributes' do
        expect(subject).to include('Req SAN')
        expect(subject).to include('administrator@contoso.local')
      end

      it 'decodes the requested application-policy extension to a friendly EKU label' do
        expect(subject).to include('Req Extns')
        expect(subject).to include('1.3.6.1.5.5.7.3.2 (Client Authentication)')
      end

      it 'does not emit non-printable bytes in the requested-extensions block' do
        ext_lines = subject.lines.select { |l| l.start_with?('    ') }.map(&:chomp).join
        expect(ext_lines).not_to match(/[^[:print:]\t]/)
      end

      it 'does not repeat subjectAltName as a raw hex blob in the extensions block' do
        ext_lines = subject.lines.select { |l| l.start_with?('    ') }.join
        expect(ext_lines).not_to include('subjectAltName')
      end

      it 'omits the template line when attributes carry no template' do
        expect(described_class.new.to_s_csr_full(csr, {})).not_to include('Req Template')
      end

      it 'tolerates a nil attributes hash' do
        expect { described_class.new.to_s_csr_full(csr, nil) }.not_to raise_error
      end

      it 'returns nil when the CSR cannot be parsed' do
        expect(described_class.new.to_s_csr_full('garbage', attributes)).to be_nil
      end
    end
  end
end
