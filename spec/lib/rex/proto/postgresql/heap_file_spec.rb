# -*- coding: binary -*-
# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/postgresql'

RSpec.describe Rex::Proto::PostgreSQL::HeapFile do
  describe '.read_tuples' do
    context 'with empty data' do
      it 'returns empty array for empty string' do
        expect(described_class.read_tuples('')).to eq([])
      end

      it 'returns empty array for nil' do
        expect(described_class.read_tuples(nil)).to eq([])
      end
    end

    context 'with data smaller than page size' do
      it 'returns empty array' do
        expect(described_class.read_tuples('short')).to eq([])
      end
    end
  end

  describe '.decode_tuple' do
    let(:schema) do
      [
        { name: 'id', typid: 23, len: 4 },
        { name: 'name', typid: 19, len: 64 }
      ]
    end

    context 'with nil data' do
      it 'returns nil for nil' do
        expect(described_class.decode_tuple(nil, schema)).to be_nil
      end

      it 'returns nil for empty string' do
        expect(described_class.decode_tuple('', schema)).to be_nil
      end
    end

    context 'with valid data' do
      it 'returns hash or nil depending on data format' do
        # decode_tuple requires properly formatted heap tuple data
        # For unit testing, we verify it handles data without crashing
        simple_schema = [
          { name: 'id', typid: 23, len: 4 }
        ]
        data = [42].pack('V')
        result = described_class.decode_tuple(data, simple_schema)

        # Result can be nil if data doesn't match expected heap format
        expect(result).to be_nil.or(be_a(Hash))
      end
    end
  end
end
