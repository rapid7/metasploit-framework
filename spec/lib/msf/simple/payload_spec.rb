require 'spec_helper'

RSpec.describe Msf::Simple::Payload do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:generator_format) { 'raw' }
  let(:generator_opts) {
    {
        'BadChars' => '',
        'Encoder' => '',
        'Options' => { 'LHOST' => '1.1.1.1', 'LPORT' => '8443' } ,
        'Format' => generator_format,
        'NoComment' => false,
        'NopSledSize' => 0,
        'MaxSize' => 0,
        'Iterations' => 1,
        'ForceEncode' => false
    }
  }

  let!(:payload_module) {
    load_and_create_module(
        ancestor_reference_names: %w{
          stagers/windows/reverse_tcp
          stages/windows/meterpreter
        },
        module_type: 'payload',
        reference_name: 'windows/meterpreter/reverse_tcp'
    )
  }

  subject(:payload) {
    described_class.generate_simple(payload_module, generator_opts)
  }

  it { expect { payload }.not_to raise_error }

  ::Msf::Simple::Buffer.transform_formats.each do |format|
    context "when given the transform format '#{format}'" do
      let(:generator_format) {  format }
      it { expect { payload }.not_to raise_error }
    end
  end
end
