# -*- coding: binary -*-
require 'spec_helper'
require 'rex/text'

RSpec.describe Rex::Proto::Thrift::ThriftData do
  subject(:instance) { described_class.new }

  it { should respond_to :data_type }
  it { should respond_to :field_id }
  it { should respond_to :data_value }

  it 'is big endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :big
  end

  it 'tracks the data type in a ThriftDataType field' do
    expect(instance.data_type).to be_a Rex::Proto::Thrift::ThriftDataType
  end

  it 'tracks the field ID in a Uint16 field' do
    expect(instance.field_id).to be_a BinData::Uint16be
  end

  it 'tracks the data value in a Choice field' do
    expect(instance.data_value).to be_a BinData::Choice
  end

  it 'sets the data type correctly by default' do
    expect(instance.data_type).to eq Rex::Proto::Thrift::ThriftDataType::T_STOP
  end

  context 'when the data type is T_STOP' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_STOP }
    let(:value) { {
      data_type: data_type
    } }
    let(:binary_s) { [data_type].pack('C') }

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

  context 'when the data type is T_BOOLEAN' do
    let(:data_type) { Rex::Proto::Thrift::ThriftDataType::T_BOOLEAN }
    let(:field_id) { rand(0xffff) }
    let(:value) { {
      data_type: data_type,
      field_id: field_id,
      data_value: true
    } }
    let(:binary_s) { [data_type, field_id, 1].pack('CnC') }

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
    let(:field_id) { rand(0xffff) }
    let(:number) { 0x7fff - rand(0xffff) }
    let(:value) { {
      data_type: data_type,
      field_id: field_id,
      data_value: number
    } }
    let(:binary_s) { [data_type, field_id, number].pack('Cns>') }

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
    let(:field_id) { rand(0xffff) }
    let(:number) { 0x7fffffff - rand(0xffffffff) }
    let(:value) { {
      data_type: data_type,
      field_id: field_id,
      data_value: number
    } }
    let(:binary_s) { [data_type, field_id, number].pack('Cnl>') }

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
    let(:field_id) { rand(0xffff) }
    let(:number) { 0x7fffffffffffffff - rand(0xffffffffffffffff) }
    let(:value) { {
      data_type: data_type,
      field_id: field_id,
      data_value: number
    } }
    let(:binary_s) { [data_type, field_id, number].pack('Cnq>') }

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
    let(:field_id) { rand(0xffff) }
    let(:text) { Rex::Text.rand_text_alphanumeric(10) }
    let(:value) { {
      data_type: data_type,
      field_id: field_id,
      data_value: text
    } }
    let(:binary_s) { [data_type, field_id, text.length].pack('CnN') + text }

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
    let(:field_id) { rand(0xffff) }
    let(:object) { [ { data_type: Rex::Proto::Thrift::ThriftDataType::T_STOP } ] }
    let(:value) { {
      data_type: data_type,
      field_id: field_id,
      data_value: object
    } }
    let(:binary_s) { [data_type, field_id, 0].pack('CnC') }

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
    let(:field_id) { rand(0xffff) }
    let(:object) { { data_type: Rex::Proto::Thrift::ThriftDataType::T_I16, members_size: 0 } }
    let(:value) { {
      data_type: data_type,
      field_id: field_id,
      data_value: object
    } }
    let(:binary_s) { [data_type, field_id, Rex::Proto::Thrift::ThriftDataType::T_I16, 0].pack('CnCN') }

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
    let(:field_id) { rand(0xffff) }
    let(:object) { { data_type: Rex::Proto::Thrift::ThriftDataType::T_I16, members_size: 0 } }
    let(:value) { {
      data_type: data_type,
      field_id: field_id,
      data_value: object
    } }
    let(:binary_s) { [data_type, field_id, Rex::Proto::Thrift::ThriftDataType::T_I16, 0].pack('CnCN') }

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
