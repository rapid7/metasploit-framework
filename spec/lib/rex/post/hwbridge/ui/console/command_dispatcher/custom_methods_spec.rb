require 'tmpdir'
require 'rex'
require 'rex/post/hwbridge/ui/console/command_dispatcher/custom_methods'

RSpec.describe Rex::Post::HWBridge::Ui::Console::CommandDispatcher::CustomMethods do
  let(:client) { double('client') }
  let(:shell) { double('shell', client: client) }

  subject(:dispatcher) { described_class.new(shell) }

  # `shell` stands in for the console shell that
  # Rex::Ui::Text::DispatcherShell::CommandDispatcher#print_error/#print_status
  # delegate to.
  before do
    allow(shell).to receive(:print_error)
    allow(shell).to receive(:print_status)
    allow(shell).to receive(:print_line)
  end

  describe '#load_methods' do
    context 'with a well-formed method_name' do
      let(:methods) do
        [
          { 'method_name' => 'custom/sample_cmd', 'method_desc' => 'Sample command', 'args' => [] }
        ]
      end

      it 'registers the command with its description' do
        dispatcher.load_methods(methods)

        expect(dispatcher.commands).to eq('sample_cmd' => 'Sample command')
      end

      it 'defines a dispatchable handler for the command' do
        dispatcher.load_methods(methods)

        expect(dispatcher.respond_to?(:cmd_sample_cmd)).to be true
      end

      it 'falls back to a default description when method_desc is absent' do
        dispatcher.load_methods([{ 'method_name' => 'custom/no_desc_cmd', 'args' => [] }])

        expect(dispatcher.commands['no_desc_cmd']).to eq('See HW manual for command description')
      end
    end

    context 'with a method_name that is not a plain identifier' do
      # method_name is external input and must never be treated as Ruby
      # source. This confirms a name carrying extra syntax is rejected
      # outright rather than passed to anything that would interpret it.
      let(:marker) { File.join(Dir.mktmpdir('hwbridge-spec'), 'marker') }
      let(:unsupported_method_name) do
        %(custom/;File.write("#{marker}","unexpected");#)
      end
      let(:methods) do
        [{ 'method_name' => unsupported_method_name, 'method_desc' => 'desc', 'args' => [] }]
      end

      it 'does not execute any code embedded in the name' do
        dispatcher.load_methods(methods)

        expect(File.exist?(marker)).to be false
      end

      it 'does not register a command for the unsupported entry' do
        dispatcher.load_methods(methods)

        expect(dispatcher.commands).to be_empty
      end

      it 'reports the unsupported method name instead of silently continuing' do
        expect(shell).to receive(:print_error).with(/Skipping custom method with unsupported name/)

        dispatcher.load_methods(methods)
      end
    end

    context 'with entries whose method_name is not a string' do
      let(:methods) do
        [
          { 'method_name' => nil, 'args' => [] },
          { 'method_name' => 42, 'args' => [] },
          { 'method_name' => ['custom/array_cmd'], 'args' => [] },
          'not a hash',
          { 'method_name' => 'custom/valid_cmd', 'method_desc' => 'Valid', 'args' => [] }
        ]
      end

      it 'skips the malformed entries and still loads later valid ones' do
        dispatcher.load_methods(methods)

        expect(dispatcher.commands).to eq('valid_cmd' => 'Valid')
      end

      it 'does not raise when later lookups run over the loaded entries' do
        dispatcher.load_methods(methods)

        expect { dispatcher.has_required_args('valid_cmd', []) }.not_to raise_error
      end
    end

    context 'with a method_name containing regex metacharacters' do
      let(:methods) do
        [{ 'method_name' => 'custom/foo.*bar', 'method_desc' => 'desc', 'args' => [] }]
      end

      it 'rejects the method name instead of defining a handler' do
        dispatcher.load_methods(methods)

        expect(dispatcher.commands).to be_empty
      end
    end
  end

  describe '#cmd_generic_handler' do
    let(:custom_methods_ext) { double('custom_methods_ext') }

    before do
      allow(client).to receive(:custom_methods).and_return(custom_methods_ext)
      dispatcher.load_methods(
        [{ 'method_name' => 'custom/sample_cmd', 'method_desc' => 'Sample command', 'args' => [] }]
      )
    end

    it 'dispatches to the hardware using the command name it was registered with' do
      expect(custom_methods_ext).to receive(:send_request).with('sample_cmd', [], anything).and_return({})

      dispatcher.cmd_sample_cmd
    end
  end

  context 'with command names that end with the same characters' do
    let(:custom_methods_ext) { double('custom_methods_ext') }
    let(:methods) do
      [
        { 'method_name' => 'custom/lock', 'method_desc' => 'Lock', 'args' => [] },
        {
          'method_name' => 'custom/unlock',
          'method_desc' => 'Unlock',
          'args' => [{ 'arg_name' => 'code', 'arg_type' => 'string', 'required' => true }]
        }
      ]
    end

    before do
      allow(client).to receive(:custom_methods).and_return(custom_methods_ext)
      dispatcher.load_methods(methods)
    end

    it 'does not apply the required arguments of unlock to lock' do
      expect(dispatcher.has_required_args('lock', [])).to be true
    end

    it 'still requires the arguments of unlock for unlock' do
      expect(dispatcher.has_required_args('unlock', [])).to be false
    end

    it 'runs lock without requiring the arguments of unlock' do
      expect(custom_methods_ext).to receive(:send_request).with('lock', [], anything).and_return({})

      dispatcher.cmd_lock
    end

    it 'shows only the usage for lock when asked for lock help' do
      expect(shell).to receive(:print_line).with('Usage: lock ').once
      expect(shell).not_to receive(:print_line).with(/code=/)
      allow(shell).to receive(:print_line).with('')

      dispatcher.cmd_generic_handler_help('lock')
    end
  end
end
