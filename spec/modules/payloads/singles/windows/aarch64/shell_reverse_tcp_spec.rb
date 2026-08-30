# frozen_string_literal: true

require 'rspec'

RSpec.describe 'singles/windows/aarch64/shell_reverse_tcp' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'windows/aarch64/shell_reverse_tcp',
      ancestor_reference_names: [
        'singles/windows/aarch64/shell_reverse_tcp'
      ]
    )
  end

  before(:each) do
    subject.datastore.merge!('LHOST' => '192.0.2.1', 'LPORT' => '4444')
  end

  describe '#generate' do
    def stub_compile_with_capture
      captured = []
      allow(subject).to receive(:compile_aarch64).and_wrap_original do |original, asm|
        compiled_asm = original.call asm
        expect(compiled_asm.length).to be > 0
        captured << compiled_asm
        compiled_asm
      end
      captured
    end

    it 'compiles the AArch64 asm and returns a non-empty binary' do
      stub_compile_with_capture
      expect(subject.generate).not_to be_empty
    end

    it 'produces different shellcode for different LPORT values' do
      stub_compile_with_capture
      raw_default = subject.generate
      subject.datastore['LPORT'] = '9999'
      raw_other = subject.generate
      expect(raw_default).not_to eq(raw_other)
    end

    it 'produces different shellcode for different LHOST values' do
      stub_compile_with_capture
      raw_default = subject.generate
      subject.datastore['LHOST'] = '198.51.100.7'
      raw_other = subject.generate
      expect(raw_default).not_to eq(raw_other)
    end

    %w[process thread none].each do |exitfunc|
      context "when EXITFUNC is #{exitfunc}" do
        it 'compiles successfully' do
          stub_compile_with_capture
          subject.datastore['EXITFUNC'] = exitfunc
          expect(subject.generate).not_to be_empty
        end
      end
    end

    context 'when LHOST is not IPv4' do
      it 'raises ArgumentError for an IPv6 LHOST' do
        subject.datastore['LHOST'] = '2001:db8::1'
        expect { subject.generate }.to raise_error(ArgumentError, /LHOST must be in IPv4 format/)
      end

      it 'raises ArgumentError for an IPv6 loopback LHOST' do
        subject.datastore['LHOST'] = '::1'
        expect { subject.generate }.to raise_error(ArgumentError, /LHOST must be in IPv4 format/)
      end

      it 'raises ArgumentError for a hostname LHOST' do
        subject.datastore['LHOST'] = 'www.example.com'
        expect { subject.generate }.to raise_error(ArgumentError, /LHOST must be in IPv4 format/)
      end
    end
  end
end
