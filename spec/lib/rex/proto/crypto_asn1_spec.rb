# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::CryptoAsn1::NtdsCaSecurityExt do
  let(:encoded) do
    "\x30\x40\xa0\x3e\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x19\x02\x01\xa0\x30" +
      "\x04\x2e\x53\x2d\x31\x2d\x35\x2d\x32\x31\x2d\x33\x34\x30\x32\x35\x38" +
      "\x37\x32\x38\x39\x2d\x31\x34\x38\x38\x37\x39\x38\x35\x33\x32\x2d\x33" +
      "\x36\x31\x38\x32\x39\x36\x39\x39\x33\x2d\x31\x31\x30\x35"
  end

  describe '.parse' do
    let(:decoded) { described_class.parse(encoded) }

    it 'decodes OtherName correctly' do
      expect(decoded[:OtherName]).to be_a RASN1::Model
    end

    it 'decodes type_id correctly' do
      type_id = decoded[:OtherName][:type_id]
      expect(type_id).to be_a RASN1::Types::ObjectId
      expect(type_id.value).to eq '1.3.6.1.4.1.311.25.2.1'
    end

    it 'decodes value correctly' do
      value = decoded[:OtherName][:value]
      expect(value).to be_a RASN1::Types::OctetString
      expect(value.value).to eq 'S-1-5-21-3402587289-1488798532-3618296993-1105'
    end
  end

  describe '#to_der' do
    it 'encodes correctly' do
      instance = described_class.new(OtherName: {
        type_id: '1.3.6.1.4.1.311.25.2.1',
        value: 'S-1-5-21-3402587289-1488798532-3618296993-1105'
      })
      expect(instance.to_der).to eq encoded
    end
  end
end
