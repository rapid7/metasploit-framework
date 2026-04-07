# -*- coding: binary -*-
# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/postgresql'

RSpec.describe Rex::Proto::PostgreSQL::Catalog do
  describe 'constants' do
    it 'defines system catalog OIDs' do
      expect(described_class::PG_TYPE).to eq(1247)
      expect(described_class::PG_ATTRIBUTE).to eq(1249)
      expect(described_class::PG_CLASS).to eq(1259)
      expect(described_class::PG_AUTHID).to eq(1260)
      expect(described_class::PG_DATABASE).to eq(1262)
    end
  end

  describe '.select_attribute_schema' do
    context 'with explicit version' do
      it 'returns V16 schema for PG16' do
        schema = described_class.select_attribute_schema([], 16)
        expect(schema).to eq(described_class::PG_ATTRIBUTE_SCHEMA_V16)
      end

      it 'returns V15 schema for PG15' do
        schema = described_class.select_attribute_schema([], 15)
        expect(schema).to eq(described_class::PG_ATTRIBUTE_SCHEMA_V15)
      end

      it 'returns V15 schema for PG12' do
        schema = described_class.select_attribute_schema([], 12)
        expect(schema).to eq(described_class::PG_ATTRIBUTE_SCHEMA_V15)
      end
    end

    context 'with auto-detection' do
      it 'falls back to V15 schema for empty tuples' do
        # When auto-detection can't determine, it defaults to V15
        schema = described_class.select_attribute_schema([], nil)
        expect(schema).to eq(described_class::PG_ATTRIBUTE_SCHEMA_V15)
      end
    end
  end

  describe '.parse_pg_class' do
    it 'returns hash from tuples' do
      # Minimal test - just verify it returns a hash
      result = described_class.parse_pg_class([])
      expect(result).to be_a(Hash)
    end
  end

  describe '.parse_pg_attribute' do
    it 'returns hash from tuples' do
      result = described_class.parse_pg_attribute([])
      expect(result).to be_a(Hash)
    end
  end
end
