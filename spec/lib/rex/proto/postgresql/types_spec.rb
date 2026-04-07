# -*- coding: binary -*-
# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/postgresql'

RSpec.describe Rex::Proto::PostgreSQL::Types do
  describe '.decode' do
    # Integer types
    context 'int2 (typid: 21)' do
      it 'decodes positive value' do
        data = [12345].pack('s<')
        expect(described_class.decode(data, 21, 2)).to eq(12345)
      end

      it 'decodes negative value' do
        data = [-100].pack('s<')
        expect(described_class.decode(data, 21, 2)).to eq(-100)
      end
    end

    context 'int4 (typid: 23)' do
      it 'decodes value' do
        data = [2147483647].pack('l<')
        expect(described_class.decode(data, 23, 4)).to eq(2147483647)
      end
    end

    context 'int8 (typid: 20)' do
      it 'decodes large value' do
        data = [9223372036854775807].pack('q<')
        expect(described_class.decode(data, 20, 8)).to eq(9223372036854775807)
      end
    end

    # Float types
    context 'float4 (typid: 700)' do
      it 'decodes value' do
        data = [3.14159].pack('e')
        result = described_class.decode(data, 700, 4)
        expect(result).to be_within(0.0001).of(3.14159)
      end
    end

    context 'float8 (typid: 701)' do
      it 'decodes value' do
        data = [2.718281828459045].pack('E')
        result = described_class.decode(data, 701, 8)
        expect(result).to be_within(0.0000001).of(2.718281828459045)
      end
    end

    # Boolean
    context 'bool (typid: 16)' do
      it 'decodes true' do
        expect(described_class.decode("\x01", 16, 1)).to be true
      end

      it 'decodes false' do
        expect(described_class.decode("\x00", 16, 1)).to be false
      end
    end

    # Text types
    context 'name (typid: 19)' do
      it 'decodes fixed-length string' do
        data = "test_table\x00" + ("\x00" * 53)
        expect(described_class.decode(data, 19, 64)).to eq('test_table')
      end
    end

    context 'char (typid: 18)' do
      it 'decodes single character' do
        expect(described_class.decode('r', 18, 1)).to eq('r')
      end
    end

    # UUID
    context 'uuid (typid: 2950)' do
      it 'decodes UUID' do
        uuid_bytes = ['550e8400e29b41d4a716446655440000'].pack('H*')
        result = described_class.decode(uuid_bytes, 2950, 16)
        expect(result).to eq('550e8400-e29b-41d4-a716-446655440000')
      end
    end

    # OID
    context 'oid (typid: 26)' do
      it 'decodes OID' do
        data = [16384].pack('V')
        expect(described_class.decode(data, 26, 4)).to eq(16384)
      end
    end

    # Network types
    context 'inet (typid: 869)' do
      it 'decodes IPv4 address' do
        # Format: family(1) + bits(1) + addr(4)
        # Family 2 = AF_INET (IPv4)
        data = [2, 32, 192, 168, 1, 100].pack('CCCCCC')
        result = described_class.decode(data, 869, 6)
        expect(result).to eq('192.168.1.100')
      end
    end

    # Bytea - returns safe string representation
    context 'bytea (typid: 17)' do
      it 'returns safe string for binary data' do
        data = "\xde\xad\xbe\xef"
        result = described_class.decode(data, 17, 4)
        # bytea returns a safe string representation
        expect(result).to be_a(String)
      end
    end

    # Unknown type fallback
    context 'unknown type' do
      it 'returns string for unhandled types' do
        data = "raw data"
        result = described_class.decode(data, 99999, -1)
        expect(result).to be_a(String)
      end
    end

    # Nil handling
    context 'nil or empty data' do
      it 'returns nil for nil' do
        expect(described_class.decode(nil, 23, 4)).to be_nil
      end

      it 'returns nil for empty string' do
        expect(described_class.decode('', 23, 4)).to be_nil
      end
    end
  end
end
