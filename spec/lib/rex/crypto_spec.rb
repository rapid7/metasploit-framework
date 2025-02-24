# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Crypto do
  describe '.bytes_to_int' do
    it 'converts an empty byte correctly' do
      expect(subject.bytes_to_int("".b)).to eq(0)
    end

    it 'converts a single null byte correctly' do
      expect(subject.bytes_to_int("\x00".b)).to eq(0)
    end

    it 'converts a single non-null byte correctly' do
      expect(subject.bytes_to_int("\x01".b)).to eq(1)
    end

    it 'converts multiple bytes correctly' do
      expect(subject.bytes_to_int("\x01\x02\x03\x04".b)).to eq(16909060)
    end
  end

  describe '.int_to_bytes' do
    it 'converts 0 to an empty byte' do
      expect(subject.int_to_bytes(0)).to eq("".b)
    end

    it 'converts to bytes correctly' do
      expect(subject.int_to_bytes(1)).to eq("\x01".b)
      expect(subject.int_to_bytes(16909060)).to eq("\x01\x02\x03\x04".b)
    end
  end
end