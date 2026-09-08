# frozen_string_literal: true

require 'spec_helper'
require 'msf/core/encoded_payload'

RSpec.describe 'stage encoding' do
  include_context 'Msf::Simple::Framework#modules loading'

  before do
    expect_to_load_module_ancestors(
      ancestor_reference_names: encoder_reference_names,
      module_type: 'encoder',
      modules_path: modules_path
    )

    allow(framework.encoders).to receive(:rank_modules).and_wrap_original do |original, *args|
      original.call(*args).select do |ref_name, _metadata|
        encoder_reference_names.include?(ref_name)
      end
    end
  end

  let(:encoder_reference_names) do
    %w[
      x64/xor_dynamic
      x64/xor
    ]
  end

  let(:payload) do
    load_and_create_module(
      ancestor_reference_names: %w[singles/linux/x64/shell_bind_tcp],
      module_type: 'payload',
      reference_name: 'linux/x64/shell_bind_tcp'
    )
  end

  let(:badchars) { "\x00\x0a\x0d".b }

  let(:encoded_payload) do
    Msf::EncodedPayload.new(
      framework,
      payload,
      {
        'BadChars' => badchars,
        'EncoderOptions' => {
          'SaveRegisters' => 'rdi'
        },
        'ForceEncode' => true,
        'ForceSaveRegisters' => true
      }
    )
  end

  before do
    encoded_payload.generate("RAW\x00".b)
  end

  it 'skips x64/xor_dynamic when rdi must be preserved' do
    expect(encoded_payload.encoder.refname).not_to eq('x64/xor_dynamic')
  end

  it 'encodes the payload' do
    expect(encoded_payload.encoded).not_to include(badchars)
  end
end
