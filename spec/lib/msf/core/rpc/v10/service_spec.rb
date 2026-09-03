require 'spec_helper'
require 'msf/core/rpc/v10/service'

RSpec.describe Msf::RPC::Service do
  let(:request_class) do
    Struct.new(:request_method, :headers, :body) do
      def method
        request_method
      end
    end
  end

  subject(:service) do
    described_class.allocate.tap do |instance|
      instance.handlers = { 'health' => health_handler }
      instance.str_encoding = Encoding::UTF_8
      instance.dispatcher_timeout = 1
    end
  end

  let(:health_handler) do
    Class.new do
      def rpc_check_noauth
        { 'status' => 'UP' }
      end
    end.new
  end

  it 'rejects an oversized body before MessagePack deserialization' do
    request = request_class.new('POST', { 'Content-Type' => 'binary/message-pack' }, 'A' * (described_class::MAX_REQUEST_SIZE + 1))
    allow(MessagePack).to receive(:unpack).and_call_original

    expect { service.process(request) }.to raise_error(ArgumentError, /request body is too large/i)
    expect(MessagePack).not_to have_received(:unpack)
  end

  it 'continues to process a valid request within the limit' do
    body = MessagePack.pack(['health.check'])
    request = request_class.new('POST', { 'Content-Type' => 'binary/message-pack' }, body)

    expect(service.process(request)).to eq('status' => 'UP')
  end
end
