# -*- coding:binary -*-

require 'spec_helper'

# Builds a module instance with a stubbed framework, matching the construction
# pattern used elsewhere in this project's specs. The datastore wired up
# during initialize is left intact so deregistered_keys state is preserved.
def build_mod_with_framework(klass, framework)
  mod = klass.new
  allow(mod).to receive(:framework).and_return(framework)
  mod
end

RSpec.describe Msf::ModuleDataStore do
  let(:framework_datastore) { Msf::DataStore.new }
  let(:framework) { instance_double(Msf::Framework, datastore: framework_datastore) }

  let(:mod_class) do
    Class.new(Msf::Auxiliary) do
      include Msf::Simple::Auxiliary

      def initialize
        super(
          'Name'        => 'Test Module',
          'Description' => 'Test module with RHOST deregistered',
          'Author'      => ['spec'],
          'License'     => MSF_LICENSE
        )
        register_options(
          [
            Msf::OptAddress.new('RHOST', [true,  'The remote host', nil]),
            Msf::OptAddress.new('LHOST', [false, 'The local host',  nil])
          ]
        )
        deregister_options('RHOST')
      end
    end
  end

  subject(:mod) { build_mod_with_framework(mod_class, framework) }

  describe '#merge!' do
    context 'when merging a DataStore containing a deregistered key' do
      let(:source) do
        ds = Msf::DataStore.new
        ds['RHOST'] = '192.0.2.1'
        ds['LHOST'] = '192.0.2.2'
        ds
      end

      it 'strips the deregistered key' do
        mod.datastore.merge!(source)
        expect(mod.datastore['RHOST']).to be_nil
      end

      it 'preserves registered keys' do
        mod.datastore.merge!(source)
        expect(mod.datastore['LHOST']).to eq('192.0.2.2')
      end
    end

    context 'when merging a plain Hash containing a deregistered key' do
      it 'strips the deregistered key' do
        mod.datastore.merge!('RHOST' => '192.0.2.1', 'LHOST' => '192.0.2.2')
        expect(mod.datastore['RHOST']).to be_nil
      end

      it 'preserves registered keys' do
        mod.datastore.merge!('RHOST' => '192.0.2.1', 'LHOST' => '192.0.2.2')
        expect(mod.datastore['LHOST']).to eq('192.0.2.2')
      end
    end
  end

  describe '#reverse_merge!' do
    context 'when reverse-merging a DataStore containing a deregistered key' do
      let(:source) do
        ds = Msf::DataStore.new
        ds['RHOST'] = '192.0.2.1'
        ds['LHOST'] = '192.0.2.2'
        ds
      end

      it 'strips the deregistered key' do
        mod.datastore.reverse_merge!(source)
        expect(mod.datastore['RHOST']).to be_nil
      end

      it 'preserves registered keys' do
        mod.datastore.reverse_merge!(source)
        expect(mod.datastore['LHOST']).to eq('192.0.2.2')
      end
    end
  end

  describe '#search_for' do
    context 'when the key has been deregistered' do
      it 'does not expose a value set in the global framework datastore' do
        framework_datastore['RHOST'] = '192.0.2.1'
        expect(mod.datastore['RHOST']).to be_nil
      end
    end
  end

  context 'when no options have been deregistered' do
    let(:full_mod_class) do
      Class.new(Msf::Auxiliary) do
        include Msf::Simple::Auxiliary

        def initialize
          super(
            'Name'        => 'Test Module (all options registered)',
            'Description' => 'Test module with no deregistered options',
            'Author'      => ['spec'],
            'License'     => MSF_LICENSE
          )
          register_options(
            [
              Msf::OptAddress.new('RHOST', [true,  'The remote host', nil]),
              Msf::OptAddress.new('LHOST', [false, 'The local host',  nil])
            ]
          )
        end
      end
    end

    subject(:full_mod) { build_mod_with_framework(full_mod_class, framework) }

    it 'stores and returns all assigned options' do
      full_mod.datastore['RHOST'] = '192.0.2.1'
      full_mod.datastore['LHOST'] = '192.0.2.2'

      expect(full_mod.datastore['RHOST']).to eq('192.0.2.1')
      expect(full_mod.datastore['LHOST']).to eq('192.0.2.2')
    end

    it 'stores all options passed via _import_extra_options' do
      full_mod._import_extra_options('Options' => { 'RHOST' => '192.0.2.1', 'LHOST' => '192.0.2.2' })

      expect(full_mod.datastore['RHOST']).to eq('192.0.2.1')
      expect(full_mod.datastore['LHOST']).to eq('192.0.2.2')
    end
  end

  context 'when a mixin registers options that the including module deregisters' do
    let(:parent_mod_class) do
      Class.new(Msf::Auxiliary) do
        include Msf::Simple::Auxiliary

        def initialize
          super(
            'Name'        => 'Parent HTTP Module',
            'Description' => 'Registers HttpUsername/HttpPassword',
            'Author'      => ['spec'],
            'License'     => MSF_LICENSE
          )
          register_options(
            [
              Msf::OptString.new('HttpUsername', [false, 'The HTTP username', '']),
              Msf::OptString.new('HttpPassword', [false, 'The HTTP password', ''])
            ]
          )
        end
      end
    end

    let(:child_mod_class) do
      Class.new(Msf::Auxiliary) do
        include Msf::Simple::Auxiliary

        def initialize
          super(
            'Name'        => 'Child HTTP Module',
            'Description' => 'Deregisters HttpUsername/HttpPassword',
            'Author'      => ['spec'],
            'License'     => MSF_LICENSE
          )
          register_options(
            [
              Msf::OptString.new('HttpUsername', [false, 'The HTTP username', '']),
              Msf::OptString.new('HttpPassword', [false, 'The HTTP password', ''])
            ]
          )
          deregister_options('HttpUsername', 'HttpPassword')
        end
      end
    end

    let(:parent_mod) { build_mod_with_framework(parent_mod_class, framework) }
    let(:child_mod)  { build_mod_with_framework(child_mod_class,  framework) }

    context 'when the parent merges its datastore into the child' do
      before do
        parent_mod.datastore['HttpUsername'] = 'foo'
        parent_mod.datastore['HttpPassword'] = 'Password1!'
      end

      it 'strips HttpUsername from the child' do
        child_mod.datastore.merge!(parent_mod.datastore)
        expect(child_mod.datastore['HttpUsername']).to be_blank
      end

      it 'strips HttpPassword from the child' do
        child_mod.datastore.merge!(parent_mod.datastore)
        expect(child_mod.datastore['HttpPassword']).to be_blank
      end
    end

    context 'when the global framework datastore has values for the deregistered options' do
      before do
        framework_datastore['HttpUsername'] = 'global_admin'
        framework_datastore['HttpPassword'] = 'global_secret'
      end

      it 'does not expose HttpUsername on the child' do
        expect(child_mod.datastore['HttpUsername']).to be_blank
      end

      it 'does not expose HttpPassword on the child' do
        expect(child_mod.datastore['HttpPassword']).to be_blank
      end
    end

    context 'when no values have been set externally' do
      it 'returns blank for HttpUsername' do
        expect(child_mod.datastore['HttpUsername']).to be_blank
      end

      it 'returns blank for HttpPassword' do
        expect(child_mod.datastore['HttpPassword']).to be_blank
      end
    end
  end

  context 'when share_datastore is used' do
    # Simulates the create_multihandler sequence in post/multi/manage/shell_to_meterpreter:
    #   pay.datastore['LHOST'] = lhost
    #   pay.datastore['LPORT'] = lport
    #   mh.share_datastore(pay.datastore)
    #   mh.datastore['PAYLOAD']   = payload_name
    #   mh.datastore['EXITFUNC']  = 'thread'
    #   mh.datastore['WORKSPACE'] = workspace
    let(:handler_mod_class) do
      Class.new(Msf::Exploit) do
        include Msf::Simple::Exploit

        def initialize
          super(
            'Name'           => 'Mock Multi Handler',
            'Description'    => 'Simulates exploit/multi/handler',
            'Author'         => ['spec'],
            'License'        => MSF_LICENSE,
            'DisclosureDate' => '2024-01-01',
            'Notes'          => { 'Stability' => [], 'Reliability' => [], 'SideEffects' => [] }
          )
          register_options(
            [
              Msf::OptString.new('PAYLOAD',   [true,  'Payload to use']),
              Msf::OptString.new('EXITFUNC',  [false, 'Exit technique', 'thread']),
              Msf::OptString.new('WORKSPACE', [false, 'Workspace']),
              Msf::OptAddressLocal.new('LHOST', [false, 'Local host']),
              Msf::OptPort.new('LPORT',         [true,  'Local port', 4444])
            ]
          )
        end
      end
    end

    let(:payload_mod_class) do
      Class.new(Msf::Auxiliary) do
        def initialize
          super(
            'Name'        => 'Mock Payload',
            'Description' => 'Simulates a payload module datastore',
            'Author'      => ['spec'],
            'License'     => MSF_LICENSE
          )
          register_options(
            [
              Msf::OptAddressLocal.new('LHOST', [false, 'Local host']),
              Msf::OptPort.new('LPORT',         [true,  'Local port', 4444])
            ]
          )
        end
      end
    end

    let(:handler_mod) { build_mod_with_framework(handler_mod_class, framework) }
    let(:payload_mod) { build_mod_with_framework(payload_mod_class, framework) }

    before do
      payload_mod.datastore['LHOST'] = '192.0.2.1'
      payload_mod.datastore['LPORT'] = 4433

      handler_mod.share_datastore(payload_mod.datastore)

      handler_mod.datastore['PAYLOAD']   = 'windows/x64/meterpreter/reverse_tcp'
      handler_mod.datastore['EXITFUNC']  = 'thread'
      handler_mod.datastore['WORKSPACE'] = 'default'
    end

    it 'preserves LHOST' do
      expect(handler_mod.datastore['LHOST']).to eq('192.0.2.1')
    end

    it 'preserves LPORT' do
      expect(handler_mod.datastore['LPORT']).to eq(4433)
    end

    it 'preserves PAYLOAD' do
      expect(handler_mod.datastore['PAYLOAD']).to eq('windows/x64/meterpreter/reverse_tcp')
    end

    it 'preserves EXITFUNC' do
      expect(handler_mod.datastore['EXITFUNC']).to eq('thread')
    end

    it 'preserves WORKSPACE' do
      expect(handler_mod.datastore['WORKSPACE']).to eq('default')
    end
  end

  context 'when an option is deregistered and then re-registered with a new definition' do
    let(:mod_class) do
      Class.new(Msf::Auxiliary) do
        include Msf::Simple::Auxiliary

        def initialize
          super(
            'Name'        => 'Test Module (deregister then re-register)',
            'Description' => 'Re-registers a previously deregistered option',
            'Author'      => ['spec'],
            'License'     => MSF_LICENSE
          )
          register_options(
            [
              Msf::OptEnum.new('FETCH_COMMAND', [true, 'Fetch command', 'CERTUTIL', %w[CURL TFTP CERTUTIL]])
            ]
          )
          deregister_options('FETCH_COMMAND')
          register_options(
            [
              Msf::OptEnum.new('FETCH_COMMAND', [true, 'Fetch command', 'CURL', %w[CURL]])
            ]
          )
        end
      end
    end

    subject(:mod) { build_mod_with_framework(mod_class, framework) }

    it 'returns the new default' do
      expect(mod.datastore['FETCH_COMMAND']).to eq('CURL')
    end

    it 'accepts writes to the re-registered option' do
      mod.datastore['FETCH_COMMAND'] = 'CURL'
      expect(mod.datastore['FETCH_COMMAND']).to eq('CURL')
    end

    it 'does not use the old deregistered default' do
      expect(mod.datastore['FETCH_COMMAND']).not_to eq('CERTUTIL')
    end
  end
end
