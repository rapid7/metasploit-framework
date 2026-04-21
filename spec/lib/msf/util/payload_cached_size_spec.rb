# frozen_string_literal: true

require 'spec_helper'
require 'ostruct'
require 'msf/util/payload_cached_size'

RSpec.describe Msf::Util::PayloadCachedSize do
  describe '.update_stage_sizes_constant' do
    let(:original_data) do
      <<~RUBY
        module MetasploitModule
          CachedSize = 123
        end
      RUBY
    end

    let(:stages_with_sizes) do
      [
        { stage: instance_double(Msf::Module, refname: 'stage_one'), size: 111 },
        { stage: instance_double(Msf::Module, refname: 'stage_two'), size: 222 }
      ]
    end

    it 'replaces an existing CachedSizeOverrides value with a new one' do
      data = <<~RUBY
        module MetasploitModule
          CachedSize = 123
          CachedSizeOverrides = {"old_stage" => 999}
        end
      RUBY
      stages_with_sizes = [
        { stage: instance_double(Msf::Module, refname: 'stage_new'), size: 555 }
      ]
      result = described_class.update_stage_sizes_constant(data, stages_with_sizes)
      expect(result).to include('CachedSizeOverrides = {"stage_new" => 555}')
    end

    it 'adds CachedSizeOverrides with correct values' do
      result = described_class.update_stage_sizes_constant(original_data, stages_with_sizes)
      expect(result).to include('CachedSizeOverrides = {"stage_one" => 111, "stage_two" => 222}')
    end

    it 'removes previous CachedSizeStages and CachedSizeOverrides lines' do
      data = <<~RUBY
        module MetasploitModule
          CachedSize = 123
          CachedSizeOverrides = something
        end
      RUBY
      result = described_class.update_stage_sizes_constant(data, stages_with_sizes)
      expect(result).to include('CachedSizeOverrides = {"stage_one" => 111, "stage_two" => 222}')
    end

    it 'returns data unchanged if no stages_with_sizes' do
      result = described_class.update_stage_sizes_constant(original_data, [])
      expect(result).to eq(original_data)
    end
  end

  describe '.cache_size_errors_for' do
    let(:framework) { instance_double('Msf::Framework') }
    let(:mod) do
      instance_double(Msf::Payload, cached_size: 100, shortname: 'foo').tap do |m|
        allow(m).to receive(:send).with(:module_info).and_return({})
        allow(m).to receive(:arch_to_s).and_return(nil)
      end
    end

    context 'when payload is dynamic and marked as dynamic' do
      it 'returns nil (no error)' do
        allow(described_class).to receive(:is_dynamic?).with(framework, mod).and_return(true)
        allow(mod).to receive(:dynamic_size?).and_return(true)
        allow(mod).to receive(:cached_size).and_return(100)
        expect(described_class.cache_size_errors_for(framework, mod)).to be_nil
      end
    end

    context 'when payload is dynamic but not marked as dynamic' do
      it 'returns an error message' do
        allow(described_class).to receive(:is_dynamic?).with(framework, mod).and_return(true)
        allow(mod).to receive(:dynamic_size?).and_return(false)
        allow(mod).to receive(:cached_size).and_return(100)
        expect(described_class.cache_size_errors_for(framework, mod)).to match(/CacheSize must be set to :dynamic/)
      end
    end

    context 'when payload is static but missing CachedSize' do
      it 'returns an error message' do
        allow(described_class).to receive(:is_dynamic?).with(framework, mod).and_return(false)
        allow(mod).to receive(:dynamic_size?).and_return(false)
        allow(mod).to receive(:cached_size).and_return(nil)
        expect(described_class.cache_size_errors_for(framework, mod)).to match(/missing CachedSize/)
      end
    end

    context 'when payload is static and CachedSize matches generated size' do
      it 'returns nil (no error)' do
        allow(described_class).to receive(:is_dynamic?).with(framework, mod).and_return(false)
        allow(mod).to receive(:dynamic_size?).and_return(false)
        allow(mod).to receive(:cached_size).and_return(100)
        allow(mod).to receive(:shortname).and_return('foo')
        allow(mod).to receive_message_chain(:replicant, :generate_simple).and_return('A' * 100)
        expect(described_class.cache_size_errors_for(framework, mod)).to be_nil
      end
    end

    context 'when payload is static and CachedSize does not match generated size' do
      it 'returns an error message' do
        allow(described_class).to receive(:is_dynamic?).with(framework, mod).and_return(false)
        allow(mod).to receive(:dynamic_size?).and_return(false)
        allow(mod).to receive(:cached_size).and_return(100)
        allow(mod).to receive(:shortname).and_return('foo')
        allow(mod).to receive_message_chain(:replicant, :generate_simple).and_return('A' * 99)
        expect(described_class.cache_size_errors_for(framework, mod)).to match(/after one generation was 99/)
      end
    end
  end
end
