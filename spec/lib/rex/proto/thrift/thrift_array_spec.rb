# -*- coding: binary -*-
require 'spec_helper'
require 'rex/text'

RSpec.describe Rex::Proto::Thrift::ThriftArray do
  context 'when the data type is T_BOOLEAN' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_BOOLEAN }
    let(:value) { {
      data_type: data_type,
      members: [ true ]
    } }
    let(:binary_s) { [data_type, 1, 1].pack('CNC') }

    describe '#to_binary_s' do
      it 'should correctly encode' do
        expect(described_class.new(value).to_binary_s).to eq binary_s
      end
    end

    describe '.read' do
      it 'should correctly decode' do
        expect(described_class.read(binary_s).snapshot.keep_if { |k,_| value.key? k }).to eq value
      end
    end
  end

  context 'when the data type is T_I16' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_I16 }
    let(:number) { 0x7fff - rand(0xffff) }
    let(:value) { {
      data_type: data_type,
      members: [ number ]
    } }
    let(:binary_s) { [data_type, 2, number].pack('CNs>') }

    describe '#to_binary_s' do
      it 'should correctly encode' do
        expect(described_class.new(value).to_binary_s).to eq binary_s
      end
    end

    describe '.read' do
      it 'should correctly decode' do
        expect(described_class.read(binary_s).snapshot.keep_if { |k,_| value.key? k }).to eq value
      end
    end
  end

  context 'when the data type is T_I32' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_I32 }
    let(:number) { 0x7fffffff - rand(0xffffffff) }
    let(:value) { {
      data_type: data_type,
      members: [ number ]
    } }
    let(:binary_s) { [data_type, 4, number].pack('CNl>') }

    describe '#to_binary_s' do
      it 'should correctly encode' do
        expect(described_class.new(value).to_binary_s).to eq binary_s
      end
    end

    describe '.read' do
      it 'should correctly decode' do
        expect(described_class.read(binary_s).snapshot.keep_if { |k,_| value.key? k }).to eq value
      end
    end
  end

  context 'when the data type is T_I64' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_I64 }
    let(:number) { 0x7fffffffffffffff - rand(0xffffffffffffffff) }
    let(:value) { {
      data_type: data_type,
      members: [ number ]
    } }
    let(:binary_s) { [data_type, 8, number].pack('CNq>') }

    describe '#to_binary_s' do
      it 'should correctly encode' do
        expect(described_class.new(value).to_binary_s).to eq binary_s
      end
    end

    describe '.read' do
      it 'should correctly decode' do
        expect(described_class.read(binary_s).snapshot.keep_if { |k,_| value.key? k }).to eq value
      end
    end
  end

  context 'when the data type is T_UTF7' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_UTF7 }
    let(:text) { Rex::Text.rand_text_alphanumeric(10) }
    let(:value) { {
      data_type: data_type,
      members: [ text ]
    } }
    let(:binary_s) { [data_type, text.length + 4, text.length].pack('CNN') + text }

    describe '#to_binary_s' do
      it 'should correctly encode' do
        expect(described_class.new(value).to_binary_s).to eq binary_s
      end
    end

    describe '.read' do
      it 'should correctly decode' do
        expect(described_class.read(binary_s).snapshot.keep_if { |k,_| value.key? k }).to eq value
      end
    end
  end

  context 'when the data type is T_STRUCT' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_STRUCT }
    # use an empty struct
    let(:object) { [ { data_type: Rex::Proto::Thrift::ThriftDataType::T_STOP } ] }
    let(:value) { {
      data_type: data_type,
      members: [ object ]
    } }
    let(:binary_s) { [data_type, 1, 0].pack('CNC') }

    describe '#to_binary_s' do
      it 'should correctly encode' do
        expect(described_class.new(value).to_binary_s).to eq binary_s
      end
    end

    describe '.read' do
      it 'should correctly decode' do
        expect(described_class.read(binary_s).snapshot.keep_if { |k,_| value.key? k }).to eq value
      end
    end
  end

  context 'when the data type is T_SET' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_SET }
    # use an empty set
    let(:object) { { data_type: Rex::Proto::Thrift::ThriftDataType::T_I16, members_size: 0 } }
    let(:value) { {
      data_type: data_type,
      members: [ object ]
    } }
    let(:binary_s) { [data_type, 5, Rex::Proto::Thrift::ThriftDataType::T_I16, 0].pack('CNCN') }

    describe '#to_binary_s' do
      it 'should correctly encode' do
        expect(described_class.new(value).to_binary_s).to eq binary_s
      end
    end

    describe '.read' do
      it 'should correctly decode' do
        expect(described_class.read(binary_s).snapshot.keep_if { |k,_| value.key? k }).to eq value
      end
    end
  end

  context 'when the data type is T_LIST' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_LIST }
    # use an empty set
    let(:object) { { data_type: Rex::Proto::Thrift::ThriftDataType::T_I16, members_size: 0 } }
    let(:value) { {
      data_type: data_type,
      members: [ object ]
    } }
    let(:binary_s) { [data_type, 5, Rex::Proto::Thrift::ThriftDataType::T_I16, 0].pack('CNCN') }

    describe '#to_binary_s' do
      it 'should correctly encode' do
        expect(described_class.new(value).to_binary_s).to eq binary_s
      end
    end

    describe '.read' do
      it 'should correctly decode' do
        expect(described_class.read(binary_s).snapshot.keep_if { |k,_| value.key? k }).to eq value
      end
    end
  end
end
