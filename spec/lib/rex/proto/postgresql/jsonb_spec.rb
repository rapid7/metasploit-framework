# -*- coding: binary -*-
# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/postgresql'

RSpec.describe Rex::Proto::PostgreSQL::Jsonb do
  describe '.parse' do
    context 'with nil or empty data' do
      it 'returns nil for nil' do
        expect(described_class.parse(nil)).to be_nil
      end

      it 'returns nil for empty string' do
        expect(described_class.parse('')).to be_nil
      end

      it 'returns nil for data shorter than 5 bytes' do
        expect(described_class.parse("\x01\x00\x00")).to be_nil
      end
    end

    context 'with malformed data' do
      it 'handles malformed data gracefully' do
        expect { described_class.parse("\x01\xff\xff\xff\xff\xff") }.not_to raise_error
      end
    end
  end

  describe 'NumericDecoder' do
    describe '.decode' do
      context 'with positive integer' do
        it 'decodes simple positive number' do
          # ndigits=1, weight=0, sign=0 (positive), dscale=0, digit=42
          header = [1, 0, 0x0000, 0].pack('s<s<S<S<')
          digits = [42].pack('v')
          data = header + digits
          result = Rex::Proto::PostgreSQL::Jsonb::NumericDecoder.decode(data)
          expect(result).to eq(42)
        end
      end

      context 'with negative integer' do
        it 'decodes negative number' do
          # ndigits=1, weight=0, sign=0x4000 (negative), dscale=0, digit=100
          header = [1, 0, 0x4000, 0].pack('s<s<S<S<')
          digits = [100].pack('v')
          data = header + digits
          result = Rex::Proto::PostgreSQL::Jsonb::NumericDecoder.decode(data)
          expect(result).to eq(-100)
        end
      end

      context 'with decimal number' do
        it 'decodes number with decimal places' do
          # 12.34 = weight=0, dscale=2, digits=[12, 3400]
          header = [2, 0, 0x0000, 2].pack('s<s<S<S<')
          digits = [12, 3400].pack('vv')
          data = header + digits
          result = Rex::Proto::PostgreSQL::Jsonb::NumericDecoder.decode(data)
          expect(result).to be_within(0.01).of(12.34)
        end
      end

      context 'with edge cases' do
        it 'returns 0 for empty digits' do
          header = [0, 0, 0x0000, 0].pack('s<s<S<S<')
          result = Rex::Proto::PostgreSQL::Jsonb::NumericDecoder.decode(header)
          expect(result).to eq(0)
        end

        it 'handles nil data' do
          expect(Rex::Proto::PostgreSQL::Jsonb::NumericDecoder.decode(nil)).to be_nil
        end
      end
    end
  end
end
