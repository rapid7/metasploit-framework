# -*- coding:binary -*-
require 'spec_helper'

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
