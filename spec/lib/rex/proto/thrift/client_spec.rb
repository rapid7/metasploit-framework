# -*- coding: binary -*-
require 'spec_helper'
require 'rex/text'

RSpec.describe Rex::Proto::Thrift::Client do
  let(:target_host) { '127.0.0.1' }
  let(:target_port) { 1234 }
  subject(:instance) { described_class.new(target_host, target_port) }

  it { should respond_to :host }
  it { should respond_to :port }
  it { should respond_to :ssl }
  it { should respond_to :timeout }

  it 'should default SSL to false' do
    expect(instance.ssl).to eq false
  end

  describe '#call' do
    let(:method_name) { Rex::Text.rand_text_alphanumeric(10) }

    it 'calls the function and returns the result' do
      allow(Rex::Proto::Thrift::ThriftHeader).to receive(:new).and_call_original
      expect(subject).to receive(:send_raw).with("\x80\x01\x00\x01\x00\x00\x00\n#{method_name}\x00\x00\x00\x00\x00".b).and_return(nil)
      expect(subject).to receive(:recv_raw).with(timeout: subject.timeout).and_return("\x80\x01\x00\x02\x00\x00\x00\n#{method_name}\x00\x00\x00\x00\x00".b)
      result = instance.call(method_name, { data_type: Rex::Proto::Thrift::ThriftDataType::T_STOP })
      expect(Rex::Proto::Thrift::ThriftHeader).to have_received(:new).with(method_name: method_name, message_type: Rex::Proto::Thrift::ThriftMessageType::CALL)
      expect(result).to be_a Array
      expect(result[0]).to eq({ data_type: Rex::Proto::Thrift::ThriftDataType::T_STOP })
    end

    it 'raises UnexpectedReplyError on an unexpected message type' do
      expect(subject).to receive(:send_raw).with("\x80\x01\x00\x01\x00\x00\x00\n#{method_name}\x00\x00\x00\x00\x00".b).and_return(nil)
      expect(subject).to receive(:recv_raw).with(timeout: subject.timeout).and_return("\x80\x01\x00\x01\x00\x00\x00\n#{method_name}\x00\x00\x00\x00\x00".b)
      expect {
        instance.call(method_name, { data_type: Rex::Proto::Thrift::ThriftDataType::T_STOP })
      }.to raise_error(Rex::Proto::Thrift::Error::UnexpectedReplyError)
    end

    it 'raises UnexpectedReplyError on an unexpected method name' do
      expect(subject).to receive(:send_raw).with("\x80\x01\x00\x01\x00\x00\x00\n#{method_name}\x00\x00\x00\x00\x00".b).and_return(nil)
      expect(subject).to receive(:recv_raw).with(timeout: subject.timeout).and_return("\x80\x01\x00\x02\x00\x00\x00\n#{method_name.swapcase}\x00\x00\x00\x00\x00".b)
      expect {
        instance.call(method_name, { data_type: Rex::Proto::Thrift::ThriftDataType::T_STOP })
      }.to raise_error(Rex::Proto::Thrift::Error::UnexpectedReplyError)
    end
  end

  describe '#connect' do
    it 'creates a rex socket' do
      expect(Rex::Socket::Tcp).to receive(:create)
      instance.connect
    end
  end
end
