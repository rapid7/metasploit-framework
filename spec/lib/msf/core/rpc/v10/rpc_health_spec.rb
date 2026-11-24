# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Msf::RPC::Health do
  describe '.check' do
    let(:framework) { double }

    it 'returns UP when the framework version and database are available' do
      allow(framework).to receive(:version).and_return('6.5.4')
      allow(framework).to receive(:db).and_return(double)

      expect(described_class.check(framework)).to eq(status: 'UP')
    end

    it 'returns DOWN when the framework version is empty' do
      allow(framework).to receive(:version).and_return('')
      allow(framework).to receive(:db).and_return(double)

      expect(described_class.check(framework)).to eq(status: 'DOWN')
    end

    it 'returns DOWN when the database is unavailable' do
      allow(framework).to receive(:version).and_return('6.5.4')
      allow(framework).to receive(:db).and_return(nil)

      expect(described_class.check(framework)).to eq(status: 'DOWN')
    end

    it 'returns DOWN when checking the framework raises an error' do
      error = StandardError.new('database unavailable')
      allow(framework).to receive(:version).and_return('6.5.4')
      allow(framework).to receive(:db).and_raise(error)
      allow(described_class).to receive(:elog)

      expect(described_class.check(framework)).to eq(status: 'DOWN')
    end
  end
end

RSpec.describe Msf::RPC::RPC_Health do
  include_context 'Msf::Simple::Framework'

  let(:service) do
    Msf::RPC::Service.new(framework)
  end

  describe 'health.check' do
    it 'can be called without an authentication token' do
      request = Struct.new(:method, :headers, :body).new(
        'POST',
        { 'Content-Type' => 'binary/message-pack' },
        MessagePack.pack(['health.check'])
      )

      allow(Msf::RPC::Health).to receive(:check).with(framework).and_return(status: 'UP')

      expect(service.process(request)).to eq(status: 'UP')
    end
  end
end
