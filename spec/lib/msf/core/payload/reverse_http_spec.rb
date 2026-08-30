require 'spec_helper'

RSpec.describe Msf::Payload::Python::ReverseHttp do
  def create_payload(info = {})
    klass = Class.new(Msf::Payload)
    klass.include Msf::Handler::ReverseHttp
    klass.include Msf::Payload::Python
    klass.include described_class
    mod = klass.new(info)
    datastore.each { |k, v| mod.datastore[k] = v }
    mod
  end

  let(:datastore) do
    {
      'LHOST' => '127.0.0.1',
      'HttpUserAgent' => 'HttpUserAgent',
    }
  end

  let(:cached_size) { 500 }
  let(:is_dynamic_size) { false }

  before(:each) do
    allow(subject).to receive(:cached_size).and_return(cached_size)
    allow(subject).to receive(:dynamic_size?).and_return(is_dynamic_size)
  end

  describe '#generate' do
    let(:subject) { create_payload }

    context 'when the payload is static' do
      let(:cached_size) { 500 }
      let(:is_dynamic_size) { false }

      context 'when available space is nil' do
        it 'generates a payload' do
          expect(subject.generate).to be_a(String)
        end
      end

      context 'when available space is defined' do
        it 'generates a payload' do
          subject.available_space = 2000
          expect(subject.generate).to be_a(String)
        end
      end
    end

    context 'when the payload is dynamic' do
      let(:cached_size) { nil }
      let(:is_dynamic_size) { true }

      context 'when available space is nil' do
        it 'generates a payload' do
          expect(subject.generate).to be_a(String)
        end
      end

      context 'when available space is defined' do
        it 'generates a payload' do
          subject.available_space = 2000
          expect(subject.generate).to be_a(String)
        end
      end
    end
  end
end
