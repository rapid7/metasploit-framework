require 'rspec'

RSpec.describe 'singles/windows/aarch64/exec' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'windows/aarch64/exec',
      ancestor_reference_names: [
        'singles/windows/aarch64/exec'
      ]
    )
  end
  let(:cmd) { nil }
  let(:datastore_values) { { 'CMD' => cmd } }

  before(:each) do
    subject.datastore.merge!(datastore_values)
  end

  describe '#generate' do
    def expect_valid_compilation
      allow(subject).to receive(:compile_aarch64).and_wrap_original do |original, asm|
        compiled_asm = original.call asm
        expect(compiled_asm.length).to be > 0
        'mock-aarch64-compiled'
      end
      expect(subject.generate).to include 'mock-aarch64-compiled'
    end

    context 'when the CMD is notepad.exe' do
      let(:cmd) { 'notepad.exe' }

      it 'compiles successfully' do
        expect_valid_compilation
      end
    end
  end
end
