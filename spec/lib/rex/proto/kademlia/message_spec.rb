# -*- coding: binary -*-
require 'spec_helper'
require 'rex/proto/kademlia/message'

RSpec.describe Rex::Proto::Kademlia::Message do

  context 'with a body' do
    let(:type) { 1 }
    let(:body) { 'test' }
    let(:data) { "\xE4\x01test" }

    subject(:message) do
      described_class.new(type, body)
    end

    describe '#initialize' do
      it 'constructs properly' do
        expect(message.type).to eq(type)
        expect(message.body).to eq(body)
      end
    end

    describe '#to_str' do
      it 'packs properly' do
        expect(message.to_str).to eq(data)
      end
    end

    describe '#from_data' do
      it 'unpacks supported messages properly' do
        unpacked = described_class.from_data(data)
        expect(unpacked.type).to eq(type)
        expect(unpacked.body).to eq(body)
      end

      it 'raises on compressed messages' do
        expect do
          described_class.from_data("\xE5\x01test")
        end.to raise_error(NotImplementedError)
      end
    end

    describe '#==' do
      it 'respects equality' do
        expect(described_class.new(1, 'test')).to eq(described_class.new(1, 'test'))
        expect(described_class.new(1, 'test')).not_to eq(described_class.new(1, 'not'))
        expect(described_class.new(1, 'test')).not_to eq(described_class.new(2, 'test'))
        expect(described_class.new(1, 'test')).not_to eq(described_class.new(2, 'not'))
      end
    end
  end

  context 'without a body' do
    let(:type) { 2 }
    let(:body) { '' }
    let(:data) { "\xE4\x02" }

    subject(:message) do
      described_class.new(type, body)
    end

    describe '#initialize' do
      it 'constructs properly' do
        expect(message.type).to eq(type)
        expect(message.body).to eq(body)
      end
    end

    describe '#to_str' do
      it 'packs properly' do
        expect(message.to_str).to eq(data)
      end
    end

    describe '#from_data' do
      it 'unpacks supported messages properly' do
        unpacked = described_class.from_data(data)
        expect(unpacked.type).to eq(type)
        expect(unpacked.body).to eq(body)
      end

      it 'raises on compressed messages' do
        expect do
          described_class.from_data("\xE5\x01")
        end.to raise_error(NotImplementedError)
      end
    end
  end
end
