require 'spec_helper'
require 'msf/core/encoded_payload'

RSpec.describe Msf::EncodedPayload do
  include_context 'Msf::Simple::Framework#modules loading'

  before do
    expect_to_load_module_ancestors(
      ancestor_reference_names: [
        # Excellent rank
        'x86/shikata_ga_nai',
        # Great rank
        'x86/call4_dword_xor',
        'x86/xor_dynamic',
        'generic/none',
        ],
      module_type: 'encoder',
      modules_path: modules_path,
    )
  end

  let(:ancestor_reference_names) {
    # A module that doesn't require any datastore junk to generate
    %w{singles/linux/x86/shell_bind_tcp}
  }

  let(:module_type) {
    'payload'
  }

  let(:reference_name) {
    'linux/x86/shell_bind_tcp'
  }

  let(:payload) {
    load_and_create_module(
        ancestor_reference_names: ancestor_reference_names,
        module_type: module_type,
        reference_name: reference_name
    )
  }

  subject(:encoded_payload) do
    described_class.new(framework, payload, reqs)
  end

  let(:badchars) { nil }
  let(:reqs) { { 'BadChars' => badchars } }

  it 'is an Msf::EncodedPayload' do
    expect(encoded_payload).to be_a(described_class)
  end

  describe '.create' do
    subject(:encoded_payload) do
      described_class.create(payload, { 'BadChars' => badchars } )
    end

    specify { expect(encoded_payload).to respond_to(:encoded) }

    it 'is an Msf::EncodedPayload' do
      expect(encoded_payload).to be_a(described_class)
    end

    context 'when passed a valid payload instance' do
      # don't ever actually generate payload bytes
      before(:example) do
        allow_any_instance_of(described_class).to receive(:generate)
      end

      it 'returns an Msf::EncodedPayload instance' do
        expect(encoded_payload).to be_a(described_class)
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
        expect(encoded_payload.arch).to eq [ARCH_X64]
      end
    end
  end

  describe '#generate' do
    let!(:generate) { encoded_payload.generate }

    context 'with no badchars' do
      let(:badchars) { nil }

      specify 'returns the raw value' do
        expect(encoded_payload.generate("RAW")).to eql("RAW")
      end

    end

    context 'with bad characters: "\\0"' do
      let(:badchars) { "\0".force_encoding('binary') }

      specify 'chooses x86/shikata_ga_nai' do
        expect(encoded_payload.encoder.refname).to eq("x86/shikata_ga_nai")
      end

      specify do
        expect(encoded_payload.encoded).not_to include(badchars)
      end

    end
    context 'with bad characters: "\\xD9\\x00"' do
      let(:badchars) { "\xD9\x00".force_encoding('binary') }

      specify 'chooses x86/xor_dynamic' do
        expect(encoded_payload.encoder.refname).to eq("x86/xor_dynamic")
      end

      specify do
        expect(encoded_payload.encoded).not_to include(badchars)
      end

    end
    context 'with windows/meterpreter_bind_tcp and bad characters: "\\x00\\x0a\\x0d"' do
      let(:badchars) { "\x00\x0a\x0d".force_encoding('binary') }
      let(:ancestor_reference_names) {
        %w{singles/windows/meterpreter_bind_tcp}
      }

      let(:reference_name) {
        'windows/meterpreter_bind_tcp'
      }

      specify 'chooses x86/xor_dynamic' do
        expect(encoded_payload.encoder.refname).to eq("x86/xor_dynamic")
      end

      specify do
        expect(encoded_payload.encoded).not_to include(badchars)
      end

    end

  end

end
