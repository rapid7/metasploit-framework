# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Core do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:core) do
    described_class.new(driver)
  end

  describe '#cmd_set' do
    context 'when setting PAYLOAD on an exploit module' do
      let(:mod) do
        mod_klass = Class.new(Msf::Exploit) do
          def initialize
            super(
              'Name' => 'mock exploit for payload option import',
              'Description' => 'mock exploit',
              'Author' => ['Unknown'],
              'License' => MSF_LICENSE,
              'Arch' => ARCH_CMD,
              'Platform' => ['unix'],
              'Targets' => [['Automatic', {}]],
              'DefaultTarget' => 0
            )

            register_options(
              [
                Msf::Opt::RHOSTS
              ]
            )
          end
        end
        mod = mod_klass.new
        allow(mod).to receive(:framework).and_return(framework)
        mod
      end

      before(:each) do
        allow(core).to receive(:active_module).and_return(mod)
        allow(driver).to receive(:on_variable_set).and_return(true)
        # Initialize the class variable that cmd_set references for payload index lookup
        Msf::Ui::Console::CommandDispatcher::Modules.class_variable_set(:@@payload_show_results, [])
      end

      it 'imports payload options into the module datastore for immediate validation' do
        # Before setting PAYLOAD, LHOST should not be in the module's options
        expect(mod.datastore.options['LHOST']).to be_nil

        core.cmd_set('PAYLOAD', 'generic/shell_reverse_tcp')

        # After setting PAYLOAD, the payload's LHOST option should be registered
        # so that subsequent set calls validate immediately
        expect(mod.datastore.options['LHOST']).not_to be_nil
      end

      it 'validates payload options on subsequent set calls without requiring show options' do
        core.cmd_set('PAYLOAD', 'generic/shell_reverse_tcp')

        # Setting an invalid LPORT should trigger validation error
        core.cmd_set('LPORT', 'not_a_port')
        expect(@error.join).to match(/not valid for option/)
      end

      it 'updates payload options when switching to a different payload' do
        core.cmd_set('PAYLOAD', 'generic/shell_reverse_tcp')
        expect(mod.datastore.options['LHOST']).not_to be_nil

        # Switch to a bind payload - LPORT should still be present
        core.cmd_set('PAYLOAD', 'generic/shell_bind_tcp')
        expect(mod.datastore.options['LPORT']).not_to be_nil
      end
    end
  end
end

RSpec.describe Msf::Ui::Console::CommandDispatcher::Modules do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:modules_dispatcher) do
    described_class.new(driver)
  end

  describe '#import_payload_options' do
    let(:mod) do
      mod_klass = Class.new(Msf::Exploit) do
        def initialize
          super(
            'Name' => 'mock exploit for use-time payload import',
            'Description' => 'mock exploit',
            'Author' => ['Unknown'],
            'License' => MSF_LICENSE,
            'Arch' => ARCH_CMD,
            'Platform' => ['unix'],
            'Targets' => [['Automatic', {}]],
            'DefaultTarget' => 0
          )

          register_options(
            [
              Msf::Opt::RHOSTS
            ]
          )
        end
      end
      mod = mod_klass.new
      allow(mod).to receive(:framework).and_return(framework)
      mod
    end

    it 'imports reverse payload options into the module datastore' do
      expect(mod.datastore.options['LHOST']).to be_nil

      modules_dispatcher.import_payload_options(mod, 'generic/shell_reverse_tcp')

      expect(mod.datastore.options['LHOST']).not_to be_nil
      expect(mod.datastore.options['LPORT']).not_to be_nil
    end

    it 'imports bind payload options into the module datastore' do
      modules_dispatcher.import_payload_options(mod, 'generic/shell_bind_tcp')

      expect(mod.datastore.options['LPORT']).not_to be_nil
    end

    it 'does nothing when payload_name is nil and datastore has no PAYLOAD' do
      modules_dispatcher.import_payload_options(mod, nil)

      expect(mod.datastore.options['LHOST']).to be_nil
      expect(mod.datastore.options['LPORT']).to be_nil
    end

    it 'uses the datastore PAYLOAD when no explicit name is given' do
      mod.datastore['PAYLOAD'] = 'generic/shell_reverse_tcp'

      modules_dispatcher.import_payload_options(mod)

      expect(mod.datastore.options['LHOST']).not_to be_nil
    end

    it 'does nothing for an invalid payload name' do
      modules_dispatcher.import_payload_options(mod, 'nonexistent/payload')

      expect(mod.datastore.options['LHOST']).to be_nil
    end
  end
end
