require 'spec_helper'

RSpec.describe Msf::Post::Linux::Compile do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Post::Linux::Compile)
    mod
  end

  describe '#get_compiler' do
    context 'when gcc is available' do
      it 'returns gcc' do
        allow(subject).to receive(:has_gcc?).and_return(true)
        expect(subject.get_compiler).to eq('gcc')
      end
    end

    context 'when clang is available' do
      it 'returns clang' do
        allow(subject).to receive(:has_gcc?).and_return(false)
        allow(subject).to receive(:has_clang?).and_return(true)
        expect(subject.get_compiler).to eq('clang')
      end
    end

    context 'when no compiler is available' do
      it 'returns nil' do
        allow(subject).to receive(:has_gcc?).and_return(false)
        allow(subject).to receive(:has_clang?).and_return(false)
        expect(subject.get_compiler).to be_nil
      end
    end

    describe '#live_compile?' do
      context 'when COMPILE is not Auto or True' do
        it 'returns false' do
          allow(subject).to receive(:datastore).and_return({ 'COMPILE' => 'False' })
          expect(subject.live_compile?).to be false
        end
      end

      context 'when COMPILE is Auto or True' do
        it 'returns true if gcc is specified and available' do
          allow(subject).to receive(:datastore).and_return({ 'COMPILE' => 'Auto', 'COMPILER' => 'gcc' })
          allow(subject).to receive(:has_gcc?).and_return(true)
          expect(subject.live_compile?).to be true
        end

        it 'returns true if clang is specified and available' do
          allow(subject).to receive(:datastore).and_return({ 'COMPILE' => 'Auto', 'COMPILER' => 'clang' })
          allow(subject).to receive(:has_clang?).and_return(true)
          expect(subject.live_compile?).to be true
        end

        it 'returns true if Auto is specified and a compiler is available' do
          allow(subject).to receive(:datastore).and_return({ 'COMPILE' => 'Auto', 'COMPILER' => 'Auto' })
          allow(subject).to receive(:get_compiler).and_return('gcc')
          expect(subject.live_compile?).to be true
        end

        it 'raises an error if the specified compiler is not available' do
          allow(subject).to receive(:datastore).and_return({ 'COMPILE' => 'True', 'COMPILER' => 'gcc' })
          allow(subject).to receive(:has_gcc?).and_return(false)
          expect { subject.live_compile? }.to raise_error(RuntimeError, 'bad-config: gcc is not installed. Set COMPILE False to upload a pre-compiled executable.')
        end
      end

      describe '#upload_and_compile' do
        let(:source) { '/path/to/source.c' }
        let(:destination) { '/tmp/source.c' }
        let(:output) { '/tmp/output' }

        before do
          allow(subject).to receive(:get_compiler).and_return('gcc')
        end

        it 'uploads the source file and compiles it' do
          expect(subject).to receive(:upload_file).with(destination, source)
          expect(subject).to receive(:cmd_exec).with("gcc #{destination} -o #{output}")
          expect(subject).to receive(:write_file).and_return('/tmp/foo')
          allow(session).to receive(:type).and_return('meterpreter')

          subject.upload_and_compile(source, destination, output)
        end

        it 'raises an error if no compiler is available' do
          allow(subject).to receive(:get_compiler).and_return(nil)

          expect { subject.upload_and_compile(source, destination, output) }.to raise_error('No compiler available on target')
        end
      end

      describe '#strip_comments' do
        it 'removes comments from the source code' do
          source_code = <<-CODE
        // This is a single line comment
        int main() {
          /* This is a
             multi-line comment */
          printf("Hello, world!");
          return 0;
        }
          CODE

          expected_output = <<-CODE

        int main() {
        #{'  '}
          printf("Hello, world!");
          return 0;
        }
          CODE

          expect(subject.strip_comments(source_code)).to eq(expected_output)
        end
      end
    end
  end
end
