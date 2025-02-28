require 'spec_helper'

RSpec.describe Msf::Post::Linux::Compile do
  subject do
    mod = Msf::Exploit.allocate
    mod.extend(Msf::PostMixin)
    mod.extend described_class
    mod.send(:initialize, {})
    mod
  end

  before do
    allow(Rex::Text).to receive(:rand_text_alphanumeric).with(8).and_return('fixedStr')
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
        expect { subject.live_compile? }.to raise_error(Msf::Exploit::Failed, 'gcc is not installed. Set COMPILE False to upload a pre-compiled executable.')
      end
    end
  end

  describe '#upload_and_compile' do
    let(:origin) { '/path/to/source.c' }
    let(:destination) { '/tmp/source.c' }
    let(:compiled) { '/tmp/source' }
    let(:flags) { '-static' }
    let(:session) { double('Session', send: nil) }
    let(:session_type_meterpreter) { 'meterpreter' }
    let(:session_type_shell) { 'shell' }

    before do
      allow(subject).to receive(:get_compiler).and_return('gcc')
      allow(subject).to receive(:rm_f).and_return('')
      allow(subject).to receive(:chmod).and_return('')
    end

    it 'uploads the source file and compiles it on meterpreter with success' do
      allow(subject).to receive_message_chain('session.type').and_return(session_type_meterpreter)
      expect(subject).to receive(:session)
      expect(subject).to receive(:write_file).with(destination, origin)
      expect(subject).to receive(:cmd_exec).with("gcc -o '#{compiled}' '#{destination}' #{flags} && echo fixedStr").and_return('fixedStr')
      expect(subject).to receive(:rm_f).with(destination)
      expect(subject).to receive(:chmod).with(destination)

      subject.upload_and_compile(compiled, origin, flags)
    end

    it 'uploads the source file and compiles it on shell with success' do
      allow(subject).to receive_message_chain('session.type').and_return(session_type_shell)
      expect(subject).to receive(:session)
      expect(subject).to receive(:write_file).with(destination, origin)
      expect(subject).to receive(:cmd_exec).with("PATH=\"$PATH:/usr/bin/\" gcc -o '#{compiled}' '#{destination}' #{flags} && echo fixedStr").and_return('fixedStr')
      expect(subject).to receive(:rm_f).with(destination)
      expect(subject).to receive(:chmod).with(destination)

      subject.upload_and_compile(compiled, origin, flags)
    end

    it 'uploads the source file and compiles it on meterpreter but fails' do
      allow(subject).to receive_message_chain('session.type').and_return(session_type_meterpreter)
      expect(subject).to receive(:session)
      expect(subject).to receive(:write_file).with(destination, origin)
      # remove the expect line, so it will look like the compile failed
      expect(subject).to receive(:cmd_exec).with("gcc -o '#{compiled}' '#{destination}' #{flags} && echo fixedStr").and_return('Compile error')
      expect(subject).to receive(:rm_f).with(destination)

      expect { subject.upload_and_compile(compiled, origin, flags) }.to raise_error(Msf::Exploit::Failed, '/tmp/source.c failed to compile. Set COMPILE to False to upload a pre-compiled executable.')
    end

    it 'raises an error if no compiler is available' do
      allow(subject).to receive(:get_compiler).and_return(nil)
      allow(subject).to receive_message_chain('session.type').and_return(session_type_shell)

      expect { subject.upload_and_compile(compiled, origin, output) }.to raise_error(Msf::Exploit::Failed, 'Unable to find a compiler on the remote target.')
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
