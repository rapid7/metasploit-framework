# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/mssql/client_mixin'

RSpec.describe Rex::Proto::MSSQL::ClientMixin do
  let(:test_class) do
    Class.new do
      include Rex::Proto::MSSQL::ClientMixin
      
      def initialize
        @framework_module = double('framework_module')
        allow(@framework_module).to receive(:print_status)
        allow(@framework_module).to receive(:print_error)
        allow(@framework_module).to receive(:print_good)
        allow(@framework_module).to receive(:print_warning)
        allow(@framework_module).to receive(:print_line)
        allow(@framework_module).to receive(:print_prefix).and_return('')
      end
    end
  end
  
  let(:client) { test_class.new }

  describe '#mssql_parse_nbcrow' do
    let(:info) { { colinfos: [], colnames: [], errors: [] } }
    
    context 'when parsing valid NBCROW data' do
      let(:colinfos) do
        [
          { id: :string, name: 'test_col' }
        ]
      end
      
      before do
        info[:colinfos] = colinfos
        info[:colnames] = ['test_col']
      end
      
      it 'handles empty data gracefully' do
        data = ''
        result = client.mssql_parse_nbcrow(data, info)
        expect(result[:errors]).to be_empty
      end
      
      it 'handles insufficient data with fallback' do
        data = "\x00" # Not enough data for proper NBCROW parsing
        
        # Mock the fallback method
        allow(client).to receive(:mssql_parse_tds_row).and_return(info)
        
        result = client.mssql_parse_nbcrow(data, info)
        expect(result).to eq(info)
      end
    end
    
    context 'when NBCROW parsing fails' do
      let(:data) { "\x00\x01\x02" }
      let(:colinfos) do
        [
          { id: :unknown_type, name: 'test_col' }
        ]
      end
      
      before do
        info[:colinfos] = colinfos
        info[:colnames] = ['test_col']
      end
      
      it 'falls back to TDS row parsing' do
        # Mock the fallback method to return success
        fallback_info = info.dup
        fallback_info[:rows] = [['fallback_value']]
        allow(client).to receive(:mssql_parse_tds_row).and_return(fallback_info)
        
        result = client.mssql_parse_nbcrow(data, info)
        
        expect(result[:rows]).to eq([['fallback_value']])
        expect(result[:errors]).to include(a_string_matching(/NBCROW parsing failed, using TDS fallback/))
      end
    end
    
    context 'when column info is missing' do
      it 'returns early without errors' do
        data = "\x00\x01\x02"
        info[:colinfos] = nil
        
        result = client.mssql_parse_nbcrow(data, info)
        expect(result).to eq(info)
      end
    end
  end
end