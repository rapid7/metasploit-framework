require 'spec_helper'
require 'msf/core/encoded_payload'

describe Msf::EncodedPayload do
  include_context 'Msf::Simple::Framework'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'

  let(:ancestor_reference_names) {
    %w{singles/linux/x86/shell_reverse_tcp}
  }

  let(:loader) {
    loader = framework.modules.send(:loaders).find { |loader|
      loader.loadable?(modules_path)
    }

    # Override load_error so that rspec will print it instead of going to framework log
    def loader.load_error(module_path, error)
      raise error
    end

    loader
  }

  let(:modules_path) {
    Rails.application.paths['modules'].expanded.first
  }

  let(:module_type) {
    'payload'
  }

  let(:reference_name) {
    'linux/x86/shell_reverse_tcp'
  }

  let(:module_set) {
    framework.modules.module_set(module_type)
  }

  let(:payload) {
    ancestor_reference_names.each do |ancestor_reference_name|
      loaded = loader.load_module(modules_path, module_type, ancestor_reference_name)

      expect(loaded).to eq(true), "#{ancestor_reference_name} failed to load from #{modules_path}"
    end

    module_set.create(reference_name)
  }

  subject(:encoded_payload) do
    described_class.new(framework, payload, {})
  end

  it 'is an Msf::EncodedPayload' do
    expect(encoded_payload).to be_a(described_class)
  end

  describe '.create' do

    context 'when passed a valid payload instance' do

      # don't ever actually generate payload bytes
      before { described_class.any_instance.stub(:generate) }

      it 'returns an Msf::EncodedPayload instance' do
        expect(described_class.create(payload)).to be_a(described_class)
      end

    end

  end

  describe '#arch' do
    context 'when payload is linux/x86 reverse tcp' do
      let(:ancestor_reference_names) {
        %w{singles/linux/x86/shell_reverse_tcp}
      }

      let(:reference_name) {
        'linux/x86/shell_reverse_tcp'
      }

      it 'returns ["X86"]' do
        expect(encoded_payload.arch).to eq [ARCH_X86]
      end
    end

    context 'when payload is linux/x64 reverse tcp' do
      let(:ancestor_reference_names) {
        %w{singles/linux/x64/shell_reverse_tcp}
      }

      let(:reference_name) {
        'linux/x64/shell_reverse_tcp'
      }

      it 'returns ["X86_64"]' do
        expect(encoded_payload.arch).to eq [ARCH_X86_64]
      end
    end
  end
end
