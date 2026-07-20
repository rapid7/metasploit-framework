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

  describe '#mssql_parse_tds_row' do
    let(:info) { { colinfos: [], rows: [], errors: [] } }

    context 'when :int column has NULL sentinel' do
      it 'returns nil for len == 0' do
        info[:colinfos] = [{ id: :int, name: 'col1' }]
        data = [0].pack('C')
        client.mssql_parse_tds_row(data, info)
        expect(info[:rows].last).to eq([nil])
        expect(info[:errors]).to be_empty
      end

      it 'returns nil for len == 255' do
        info[:colinfos] = [{ id: :int, name: 'col1' }]
        data = [255].pack('C')
        client.mssql_parse_tds_row(data, info)
        expect(info[:rows].last).to eq([nil])
        expect(info[:errors]).to be_empty
      end

      it 'parses a 4-byte integer' do
        info[:colinfos] = [{ id: :int, name: 'col1' }]
        data = [4].pack('C') + [42].pack('V')
        client.mssql_parse_tds_row(data, info)
        expect(info[:rows].last).to eq([42])
        expect(info[:errors]).to be_empty
      end
    end

    context 'when :hex column has NULL sentinel (0xFFFF)' do
      it 'returns nil for len == 65535' do
        info[:colinfos] = [{ id: :hex, name: 'col1' }]
        data = [65535].pack('v')
        client.mssql_parse_tds_row(data, info)
        expect(info[:rows].last).to eq([nil])
        expect(info[:errors]).to be_empty
      end

      it 'parses hex data' do
        info[:colinfos] = [{ id: :hex, name: 'col1' }]
        data = [2].pack('v') + "\x41\x42"
        client.mssql_parse_tds_row(data, info)
        expect(info[:rows].last).to eq(['4142'])
        expect(info[:errors]).to be_empty
      end
    end

    context 'when :string column has NULL sentinel (0xFFFF)' do
      it 'returns nil for len == 65535' do
        info[:colinfos] = [{ id: :string, name: 'col1' }]
        data = [65535].pack('v')
        client.mssql_parse_tds_row(data, info)
        expect(info[:rows].last).to eq([nil])
        expect(info[:errors]).to be_empty
      end

      it 'parses a string value' do
        info[:colinfos] = [{ id: :string, name: 'col1' }]
        data = [3].pack('v') + "foo"
        client.mssql_parse_tds_row(data, info)
        expect(info[:rows].last).to eq(['foo'])
        expect(info[:errors]).to be_empty
      end
    end

    context 'when :guid column is NULL' do
      it 'returns nil for read_length == 0' do
        info[:colinfos] = [{ id: :guid, name: 'col1' }]
        data = [0].pack('C')
        client.mssql_parse_tds_row(data, info)
        expect(info[:rows].last).to eq([nil])
        expect(info[:errors]).to be_empty
      end
    end

    context 'when :int has invalid size' do
      it 'logs error and consumes len bytes' do
        info[:colinfos] = [{ id: :int, name: 'col1' }]
        trailing = "AFTER".b
        data = [3].pack('C') + "XXX" + trailing
        client.mssql_parse_tds_row(data, info)
        expect(info[:errors].length).to eq(1)
        expect(info[:errors].first).to match(/invalid integer size: 3/)
        expect(data).to eq(trailing)
      end
    end
  end
end
