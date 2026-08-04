# frozen_string_literal: true

require 'rspec'

RSpec.describe 'stages/windows/aarch64/shell' do
  include_context 'Msf::Simple::Framework#modules loading'

  # Stages are not standalone payloads; load the combined staged pair.
  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'windows/aarch64/shell/reverse_tcp',
      ancestor_reference_names: [
        'stagers/windows/aarch64/reverse_tcp',
        'stages/windows/aarch64/shell'
      ]
    )
  end

  before(:each) do
    subject.datastore.merge!(
      'LHOST' => '192.0.2.1',
      'LPORT' => '4444',
      'EXITFUNC' => 'process'
    )
  end

  describe '#generate_stage' do
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
      expect(subject.generate_stage).not_to be_empty
    end

    it 'produces a 420-byte stage' do
      stub_compile_with_capture
      expect(subject.generate_stage.length).to eq(420)
    end

    it 'starts with mov x22, x0 (preserve socket handle)' do
      stub_compile_with_capture
      # Encoding of `mov x22, x0` is 0xaa0003f6 (LE: f6 03 00 aa)
      expect(subject.generate_stage[0, 4]).to eq("\xf6\x03\x00\xaa".b)
    end

    %w[process thread none seh].each do |exitfunc|
      context "when EXITFUNC is #{exitfunc}" do
        it 'compiles successfully' do
          stub_compile_with_capture
          subject.datastore['EXITFUNC'] = exitfunc
          expect(subject.generate_stage).not_to be_empty
        end
      end
    end

    it 'produces different shellcode for different EXITFUNC values' do
      stub_compile_with_capture
      subject.datastore['EXITFUNC'] = 'process'
      raw_process = subject.generate_stage
      subject.datastore['EXITFUNC'] = 'thread'
      raw_thread = subject.generate_stage
      expect(raw_process).not_to eq(raw_thread)
    end

    it 'produces different shellcode for EXITFUNC=seh than process' do
      stub_compile_with_capture
      subject.datastore['EXITFUNC'] = 'process'
      raw_process = subject.generate_stage
      subject.datastore['EXITFUNC'] = 'seh'
      raw_seh = subject.generate_stage
      expect(raw_seh).not_to eq(raw_process)
    end
  end
end
