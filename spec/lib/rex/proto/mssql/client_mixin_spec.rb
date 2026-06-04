# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/mssql/client'

RSpec.describe Rex::Proto::MSSQL::ClientMixin do
  let(:client) { Rex::Proto::MSSQL::Client.allocate }

  describe '#mssql_parse_order' do
    let(:info) { { errors: [] } }

    it 'consumes the ORDER token data and returns info unchanged' do
      data = [4, 1, 2].pack('vvv')
      result = client.mssql_parse_order(data, info)
      expect(result[:errors]).to be_empty
      expect(data).to be_empty
    end

    it 'handles a single column ordinal' do
      data = [2, 3].pack('vv')
      result = client.mssql_parse_order(data, info)
      expect(result[:errors]).to be_empty
      expect(data).to be_empty
    end

    it 'preserves remaining data after the ORDER token' do
      trailing = "\xAB\xCD".b
      data = [2, 1].pack('vv') + trailing
      client.mssql_parse_order(data, info)
      expect(data).to eq(trailing)
    end

    it 'handles zero-length ORDER token' do
      data = [0].pack('v')
      result = client.mssql_parse_order(data, info)
      expect(result[:errors]).to be_empty
      expect(data).to be_empty
    end
  end

  describe '#mssql_parse_reply' do
    context 'when response contains an ORDER token (0xA9)' do
      it 'parses the ORDER token without error' do
        colmeta = [0x81].pack('C') + [1].pack('v')
        colmeta += [0, 0].pack('vv')
        colmeta += [56].pack('C')
        colmeta += [0].pack('C')

        order = [0xA9].pack('C') + [2, 1].pack('vv')
        done = [0xFD].pack('C') + [0, 0, 0].pack('vvV')

        data = colmeta + order + done
        result = client.mssql_parse_reply(data)
        expect(result[:errors]).to be_empty
      end

      it 'does not confuse ORDER token (0xA9) with NBCROW token (0xD2)' do
        colmeta = [0x81].pack('C') + [1].pack('v')
        colmeta += [0, 0].pack('vv')
        colmeta += [56].pack('C')
        colmeta += [0].pack('C')

        order = [0xA9].pack('C') + [4, 1, 2].pack('vvv')
        row = [0xD1].pack('C') + [42].pack('V')
        done = [0xFD].pack('C') + [0, 0, 1].pack('vvV')

        data = colmeta + order + row + done
        result = client.mssql_parse_reply(data)
        expect(result[:errors]).to be_empty
        expect(result[:rows]).to eq([[42]])
      end
    end
  end

  describe '#mssql_parse_nbcrow' do
    let(:info) { { colinfos: [], colnames: [], errors: [] } }

    context 'when column info is missing' do
      it 'returns early without errors' do
        data = "\x00\x01\x02"
        info[:colinfos] = nil
        result = client.mssql_parse_nbcrow(data, info)
        expect(result).to eq(info)
      end
    end

    context 'when data is empty' do
      it 'returns info unchanged' do
        info[:colinfos] = [{ id: :string, name: 'col1' }]
        data = ''
        result = client.mssql_parse_nbcrow(data, info)
        expect(result[:errors]).to be_empty
      end
    end
  end
end
