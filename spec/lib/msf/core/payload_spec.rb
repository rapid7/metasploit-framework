# frozen_string_literal: true

require 'spec_helper'
require 'msf/core/payload'

RSpec.describe Msf::Payload do
  let(:klass) { Class.new(described_class) }

  describe '.cached_size' do
    context 'when CachedSize is not defined' do
      it 'returns nil' do
        expect(klass.cached_size).to be_nil
      end
    end

    context 'when CachedSize is defined as an integer' do
      let(:klass) do
        Class.new(described_class).tap do |klass|
          klass.const_set(:CachedSize, 123)
        end
      end

      it 'returns the integer value' do
        expect(klass.cached_size).to eq(123)
      end
    end

    context 'when CachedSize is defined as :dynamic' do
      let(:klass) do
        Class.new(described_class).tap do |klass|
          klass.const_set(:CachedSize, :dynamic)
        end
      end

      it 'returns nil' do
        expect(klass.cached_size).to be_nil
      end
    end

    context 'when class is a Stager and CachedSizeOverrides is defined' do
      let(:stager_klass) do
        Class.new(described_class).tap do |klass|
          klass.send(:include, Msf::Payload::Stager)
          klass.const_set(:CachedSize, 111)
          klass.const_set(:CachedSizeOverrides, { 'windows/stage/stager' => 222 })
          klass.define_singleton_method(:refname) { 'windows/stage/stager' }
        end
      end

      it 'returns the override value for the stager refname' do
        expect(stager_klass.cached_size).to eq(222)
      end
    end
  end

  describe '#cached_size' do
    it 'delegates to .cached_size' do
      obj = klass.new
      allow(klass).to receive(:cached_size).and_return(42)
      expect(obj.cached_size).to eq(42)
    end
  end
end
