# -*- coding:binary -*-
require 'spec_helper'


RSpec.describe Rex::Proto::DNS::UpstreamResolver do
  context 'when type is black-hole' do
    let(:type) { Rex::Proto::DNS::UpstreamResolver::Type::BLACK_HOLE }
    let(:resolver) { described_class.create_black_hole }

    describe '.new_black_hole' do
      it 'is expected to set the type correctly' do
        expect(resolver.type).to eq type
      end

      it 'is expected to set the destination correctly' do
        expect(resolver.destination).to be_nil
      end
    end

    describe '#to_s' do
      it 'is expected to return the type as a string' do
        expect(resolver.to_s).to eq type.to_s
      end
    end
  end

  context 'when type is dns-server' do
    let(:type) { Rex::Proto::DNS::UpstreamResolver::Type::DNS_SERVER }
    let(:destination) { '192.0.2.10' }
    let(:resolver) { described_class.create_dns_server(destination) }

    describe '.new_dns_server' do
      it 'is expected to set the type correctly' do
        expect(resolver.type).to eq type
      end

      it 'is expected to set the destination correctly' do
        expect(resolver.destination).to eq destination
      end
    end

    describe '#to_s' do
      it 'is expected to return the nameserver IP address as a string' do
        expect(resolver.to_s).to eq destination
      end
    end
  end

  context 'when type is static' do
    let(:type) { Rex::Proto::DNS::UpstreamResolver::Type::STATIC }
    let(:resolver) { described_class.create_static }

    describe '.new_static' do
      it 'is expected to set the type correctly' do
        expect(resolver.type).to eq type
      end

      it 'is expected to set the destination correctly' do
        expect(resolver.destination).to be_nil
      end
    end

    describe '#to_s' do
      it 'is expected to return the type as a string' do
        expect(resolver.to_s).to eq type.to_s
      end
    end
  end

  context 'when type is system' do
    let(:type) { Rex::Proto::DNS::UpstreamResolver::Type::SYSTEM }
    let(:resolver) { described_class.create_system }

    describe '.new_system' do
      it 'is expected to set the type correctly' do
        expect(resolver.type).to eq type
      end

      it 'is expected to set the destination correctly' do
        expect(resolver.destination).to be_nil
      end
    end

    describe '#to_s' do
      it 'is expected to return the type as a string' do
        expect(resolver.to_s).to eq type.to_s
      end
    end
  end
end
