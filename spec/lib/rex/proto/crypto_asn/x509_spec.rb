# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::CryptoAsn1::X509::OtherName do
  let(:encoded) do
    "\xa0\x2e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03\xa0\x20" +
      "\x0c\x1e\x44\x45\x53\x4b\x54\x4f\x50\x2d\x4d\x57\x4a\x39\x4d\x4f\x45" +
      "\x43\x24\x40\x6d\x73\x66\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c"
  end

  describe '.parse' do
    let(:decoded) { described_class.parse(encoded) }

    it 'decodes otherName correctly' do
      expect(decoded[:type_id].value?).to be_truthy
      expect(decoded[:type_id]).to be_a RASN1::Types::ObjectId
      expect(decoded[:value].value?).to be_truthy
      expect(decoded[:value]).to be_a RASN1::Types::Any
    end
  end

  describe '#to_der' do
    it 'encodes correctly' do
      instance = described_class.new(
        type_id: '1.3.6.1.4.1.311.20.2.3',
        value: "\xA0 \f\x1EDESKTOP-MWJ9MOEC$@msflab.local".b
      )
      expect(instance.to_der).to eq encoded
    end
  end
end

RSpec.describe Rex::Proto::CryptoAsn1::X509::GeneralName do
  context 'when otherName is chosen' do
    let(:encoded) do
      "\xa0\x2e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03\xa0\x20\x0c" +
        "\x1e\x44\x45\x53\x4b\x54\x4f\x50\x2d\x4d\x57\x4a\x39\x4d\x4f\x45\x43" +
        "\x24\x40\x6d\x73\x66\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c"
    end

    describe '.parse' do
      let(:decoded) { described_class.parse(encoded) }

      it 'decodes otherName correctly' do
        expect(decoded[:otherName].value?).to be_truthy
        expect(decoded[:otherName]).to be_a Rex::Proto::CryptoAsn1::X509::OtherName
      end
    end

    describe '#to_der' do
      it 'encodes correctly' do
        instance = described_class.new(
          otherName: {
            type_id: '1.3.6.1.4.1.311.20.2.3',
            value: "\xA0 \f\x1EDESKTOP-MWJ9MOEC$@msflab.local".b
          }
        ).tap { |gn| gn.chosen = 0 }
        expect(instance.to_der).to eq encoded
      end
    end
  end

  context 'when rfc822Name is chosen' do
    let(:encoded) do
      "\x81\x14\x73\x70\x65\x6e\x63\x65\x72\x40\x6d\x73\x66\x6c\x61\x62\x2e" +
        "\x6c\x6f\x63\x61\x6c".b
    end

    describe '.parse' do
      let(:decoded) { described_class.parse(encoded) }

      it 'decodes rfc822Name correctly' do
        expect(decoded[:rfc822Name].value?).to be_truthy
        expect(decoded[:rfc822Name]).to be_a RASN1::Types::IA5String
        expect(decoded[:rfc822Name].value).to eq 'spencer@msflab.local'
      end
    end

    describe '#to_der' do
      it 'encodes correctly' do
        instance = described_class.new(
          rfc822Name: 'spencer@msflab.local'
        ).tap { |gn| gn.chosen = 1 }
        expect(instance.to_der).to eq encoded
      end
    end
  end

  context 'when dNSName is chosen' do
    let(:encoded) do
      "\x82\x1d\x44\x45\x53\x4b\x54\x4f\x50\x2d\x4d\x57\x4a\x39\x4d\x4f\x45" +
        "\x43\x2e\x6d\x73\x66\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c".b
    end

    describe '.parse' do
      let(:decoded) { described_class.parse(encoded) }

      it 'decodes dNSName correctly' do
        expect(decoded[:dNSName].value?).to be_truthy
        expect(decoded[:dNSName]).to be_a RASN1::Types::IA5String
        expect(decoded[:dNSName].value).to eq 'DESKTOP-MWJ9MOEC.msflab.local'
      end
    end

    describe '#to_der' do
      it 'encodes correctly' do
        instance = described_class.new(
          dNSName: 'DESKTOP-MWJ9MOEC.msflab.local'
        ).tap { |gn| gn.chosen = 2 }
        expect(instance.to_der).to eq encoded
      end
    end
  end
end

RSpec.describe Rex::Proto::CryptoAsn1::X509::SubjectAltName do
  let(:encoded) do
    "\x30\x30\xa0\x2e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03\xa0\x20" +
      "\x0c\x1e\x44\x45\x53\x4b\x54\x4f\x50\x2d\x4d\x57\x4a\x39\x4d\x4f\x45" +
      "\x43\x24\x40\x6d\x73\x66\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c"
  end

  describe '.parse' do
    let(:decoded) { described_class.parse(encoded) }

    it 'decodes GeneralNames correctly' do
      expect(decoded[:GeneralNames]).to be_a RASN1::Types::SequenceOf
      expect(decoded[:GeneralNames].length).to eq 1
      expect(decoded[:GeneralNames].value.first).to be_a Rex::Proto::CryptoAsn1::X509::GeneralName
    end
  end

  describe '#to_der' do
    it 'encodes correctly' do
      instance = described_class.new(GeneralNames: [{
        otherName: {
          type_id: '1.3.6.1.4.1.311.20.2.3',
          value: "\xA0 \f\x1EDESKTOP-MWJ9MOEC$@msflab.local".b
        }
      }]).tap { |san| san[:GeneralNames][0].chosen = 0 }
      expect(instance.to_der).to eq encoded
    end
  end
end
