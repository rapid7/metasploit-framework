require 'tmpdir'
require 'rex'
require 'rex/post/hwbridge/ui/console/command_dispatcher/custom_methods'

RSpec.describe Rex::Post::HWBridge::Ui::Console::CommandDispatcher::CustomMethods do
  let(:client) { double('client') }
  let(:other_dispatcher) { double('other_dispatcher', commands: { 'exit' => 'Exit', 'help' => 'Help' }) }
  let(:shell) { double('shell', client: client, dispatcher_stack: [other_dispatcher]) }

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

    context 'with a method_name that has several path segments' do
      let(:custom_methods_ext) { double('custom_methods_ext') }
      let(:methods) do
        [
          {
            'method_name' => 'custom/device/reset',
            'method_desc' => 'Reset the device',
            'args' => [{ 'arg_name' => 'mode', 'arg_type' => 'string', 'required' => true }]
          }
        ]
      end

      before do
        allow(client).to receive(:custom_methods).and_return(custom_methods_ext)
        dispatcher.load_methods(methods)
      end

      it 'registers only the final segment as the command' do
        expect(dispatcher.commands).to eq('reset' => 'Reset the device')
      end

      it 'does not register the earlier segments as part of the command' do
        expect(dispatcher.respond_to?(:cmd_device)).to be false
      end

      it 'still enforces the required arguments of the method' do
        expect(dispatcher.has_required_args('reset', [])).to be false
      end

      it 'dispatches the final segment to the hardware' do
        expect(custom_methods_ext).to receive(:send_request).with('reset', ['mode=full'], anything).and_return({})

        dispatcher.cmd_reset('mode=full')
      end
    end

    it 'registers a root-level method and enforces its arguments' do
      dispatcher.load_methods([{ 'method_name' => 'temperature', 'args' => [{ 'arg_name' => 'unit', 'required' => true }] }])

      expect(dispatcher.commands).to have_key('temperature')
      expect(dispatcher.has_required_args('temperature', [])).to be false
      expect(dispatcher.has_required_args('temperature', ['unit=c'])).to be true
    end

    it 'rejects unsafe characters or traversal in any part of the path' do
      names = ["custom/x HTTP/1.1\r\n\r\nGET /lock", 'control/reset?x=/lock', 'custom/./lock', 'custom/../lock', 'custom/%2e%2e/lock', 'custom/#fragment/lock']
      dispatcher.load_methods(names.map { |name| { 'method_name' => name } })

      expect(dispatcher.commands).to be_empty
    end

    context 'with a method_name that has no final segment' do
      ['custom/', 'custom/device/', '/'].each do |name|
        it "does not register a command for #{name.inspect}" do
          dispatcher.load_methods([{ 'method_name' => name, 'args' => [] }])

          expect(dispatcher.commands).to be_empty
        end
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

    context 'with a command name that is already used' do
      def load_single(name)
        dispatcher.load_methods([{ 'method_name' => "custom/#{name}", 'method_desc' => 'desc', 'args' => [] }])
      end

      %w[generic_handler generic_handler_help].each do |name|
        it "does not replace the built-in cmd_#{name} handler" do
          original = dispatcher.method("cmd_#{name}").owner

          load_single(name)

          expect(dispatcher.method("cmd_#{name}").owner).to eq(original)
        end

        it "does not register #{name} as a custom command" do
          load_single(name)

          expect(dispatcher.commands).to be_empty
        end
      end

      it 'does not overflow the stack when generic_handler is advertised' do
        allow(client).to receive(:custom_methods).and_return(double('custom_methods_ext', send_request: {}))
        load_single('generic_handler')

        expect { dispatcher.cmd_generic_handler('generic_handler') }.not_to raise_error
      end

      it 'skips a command that another dispatcher already provides' do
        load_single('exit')

        expect(dispatcher.commands).to be_empty
      end

      it 'does not define a handler for a command that another dispatcher provides' do
        load_single('exit')

        expect(dispatcher.respond_to?(:cmd_exit)).to be false
      end

      it 'reports that the command already exists' do
        expect(shell).to receive(:print_error).with(/the command 'exit' already exists/)

        load_single('exit')
      end

      it 'does not skip commands that only share a prefix with an existing one' do
        load_single('exit_now')

        expect(dispatcher.commands.keys).to eq(['exit_now'])
      end

      context 'when the same command is advertised twice' do
        let(:methods) do
          [
            { 'method_name' => 'a/lock', 'method_desc' => 'First', 'args' => [] },
            { 'method_name' => 'b/lock', 'method_desc' => 'Second', 'args' => [] }
          ]
        end

        it 'keeps the first one' do
          dispatcher.load_methods(methods)

          expect(dispatcher.commands).to eq('lock' => 'First')
        end

        it 'does not keep the duplicate for later lookups' do
          dispatcher.load_methods(methods)

          expect(dispatcher.has_required_args('lock', [])).to be true
        end

        it 'only sends the first one to the hardware' do
          custom_methods_ext = double('custom_methods_ext')
          allow(client).to receive(:custom_methods).and_return(custom_methods_ext)
          dispatcher.load_methods(methods)

          expect(custom_methods_ext).to receive(:send_request) do |_cmd, _args, kept|
            expect(kept.map { |meth| meth['method_name'] }).to eq(['a/lock'])
            {}
          end

          dispatcher.cmd_lock
        end
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

  context 'when the methods are loaded again' do
    let(:custom_methods_ext) { double('custom_methods_ext') }
    let(:methods) do
      [
        { 'method_name' => 'custom/lock', 'method_desc' => 'Lock', 'args' => [] },
        { 'method_name' => 'custom/unlock', 'method_desc' => 'Unlock', 'args' => [] }
      ]
    end

    before do
      allow(client).to receive(:custom_methods).and_return(custom_methods_ext)
      dispatcher.load_methods(methods)
    end

    context 'with the same list' do
      before { dispatcher.load_methods(methods) }

      it 'keeps the same commands' do
        expect(dispatcher.commands.keys).to contain_exactly('lock', 'unlock')
      end

      it 'does not report the commands as already existing' do
        expect(shell).not_to receive(:print_error).with(/already exists/)

        dispatcher.load_methods(methods)
      end

      it 'still dispatches the commands to the hardware' do
        expect(custom_methods_ext).to receive(:send_request).with('lock', [], anything).and_return({})

        dispatcher.cmd_lock
      end

      it 'passes the reloaded methods to the hardware request' do
        expect(custom_methods_ext).to receive(:send_request) do |_cmd, _args, kept|
          expect(kept.map { |meth| meth['method_name'] }).to eq(['custom/lock', 'custom/unlock'])
          {}
        end

        dispatcher.cmd_lock
      end
    end

    context 'with a different list' do
      let(:new_methods) { [{ 'method_name' => 'custom/reset_all', 'method_desc' => 'Reset', 'args' => [] }] }

      before { dispatcher.load_methods(new_methods) }

      it 'only keeps the commands from the new list' do
        expect(dispatcher.commands.keys).to eq(['reset_all'])
      end

      it 'removes the handlers of commands that are no longer advertised' do
        expect(dispatcher.respond_to?(:cmd_lock)).to be false
      end

      it 'dispatches the new command' do
        expect(custom_methods_ext).to receive(:send_request).with('reset_all', [], anything).and_return({})

        dispatcher.cmd_reset_all
      end
    end

    context 'with an empty list' do
      it 'removes every previously registered command' do
        dispatcher.load_methods([])

        expect(dispatcher.commands).to be_empty
      end
    end

    it 'preserves the previous methods when the refreshed list is invalid' do
      dispatcher.load_methods(nil)

      expect(dispatcher.commands.keys).to contain_exactly('lock', 'unlock')
      expect(custom_methods_ext).to receive(:send_request).with('lock', [], anything).and_return({})
      dispatcher.cmd_lock
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

  context 'with method argument definitions' do
    let(:custom_methods_ext) { double('custom_methods_ext') }

    before do
      allow(client).to receive(:custom_methods).and_return(custom_methods_ext)
    end

    it 'accepts an omitted argument list' do
      dispatcher.load_methods([{ 'method_name' => 'custom/status_cmd' }])

      expect(custom_methods_ext).to receive(:send_request).with('status_cmd', [], anything).and_return({})
      dispatcher.cmd_status_cmd
    end

    it 'treats an argument without a required flag as optional' do
      dispatcher.load_methods([{ 'method_name' => 'custom/status_cmd', 'args' => [{ 'arg_name' => 'format' }] }])

      expect(dispatcher.commands).to have_key('status_cmd')
      expect(dispatcher.has_required_args('status_cmd', [])).to be true
    end

    [nil, 'code', { 'arg_name' => 'code', 'required' => true }, ['junk'], [{ 'required' => true }], [{ 'arg_name' => 'code', 'required' => 'true' }]].each do |args|
      it "rejects malformed arguments #{args.inspect}" do
        dispatcher.load_methods([{ 'method_name' => 'custom/write', 'args' => args }])

        expect(dispatcher.commands).to be_empty
        expect(custom_methods_ext).not_to receive(:send_request)
      end
    end

    it 'does not change the hash it was given' do
      entry = { 'method_name' => 'custom/status_cmd' }

      dispatcher.load_methods([entry])

      expect(entry).to eq('method_name' => 'custom/status_cmd')
    end
  end
end
