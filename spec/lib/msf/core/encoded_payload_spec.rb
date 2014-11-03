require 'spec_helper'
require 'msf/core/encoded_payload'

describe Msf::EncodedPayload do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:ancestor_reference_names) {
    %w{singles/linux/x86/shell_reverse_tcp}
  }

  let(:module_type) {
    'payload'
  }

  let(:reference_name) {
    'linux/x86/shell_reverse_tcp'
  }

  let(:payload) {
    load_and_create_module(
        ancestor_reference_names: ancestor_reference_names,
        module_type: module_type,
        reference_name: reference_name
    )
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
