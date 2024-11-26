# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Model::TransitedEncoding do

  subject(:transited_encoding) do
    described_class.new
  end

  let(:transited_encoding_sample) do
    "0\t\xA0\x03\x02\x01\x00\xA1\x02\x04\x00"
  end

  describe '#decode' do
    it 'decodes correctly' do
      transited_encoding.decode(transited_encoding_sample)

      expect(transited_encoding.tr_type).to eq(0)
      expect(transited_encoding.contents).to eq("")

    end
  end

  describe '#encode' do
    it 'encodes correctly' do
      transited_encoding.tr_type = 0
      transited_encoding.contents = ""
      expect(transited_encoding.encode).to eq(transited_encoding_sample)
    end
  end
end
