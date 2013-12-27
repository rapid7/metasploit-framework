require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/command_dispatcher/core'

describe Msf::Ui::Console::CommandDispatcher::Core do
	include_context 'Msf::DBManager'
	include_context 'Msf::Ui::Console::Driver'

	subject(:command_dispatcher) do
		described_class.new(msf_ui_console_driver)
  end

  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher'

  it_should_behave_like 'Metasploit::Framework::Command::Dispatcher.command',
                        :search,
                        klass: Metasploit::Framework::Command::Search
  it_should_behave_like 'Metasploit::Framework::Command::Dispatcher.command',
                        :use,
                        klass: Metasploit::Framework::Command::Use

  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher::Core::ReloadAll'
  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher::Core::Spool'
  it_should_behave_like 'Msf::Ui::Console::CommandDispatcher::Core::Threads'

  context '#data_store_by_module_class_full_name' do
    subject(:data_store_by_module_class_full_name) do
      command_dispatcher.data_store_by_module_class_full_name
    end

    it { should be_a Hash }

    context 'default' do
      it { should == {} }
    end
  end

  context '#cmd_previous' do
    subject(:cmd_previous) do
      command_dispatcher.cmd_previous
    end

    context 'with previous Module::Class#full_name' do
      #
      # lets
      #

      let(:module_class_full_name_was) do
        'module/class/full/name/was'
      end

      #
      # Callbacks
      #

      before(:each) do
        command_dispatcher.instance_variable_set :@module_class_full_name_was, module_class_full_name_was
      end

      it 'calls #cmd_use with previous Module::Class#full_name' do
        expect(command_dispatcher).to receive(:cmd_use).with(module_class_full_name_was)

        cmd_previous
      end
    end

    context 'without previous Module::Class#full_name' do
      include_context 'output'

      it 'prints error' do
        output.should include("There isn't a previous module at the moment")
      end
    end
  end

  context '#metasploit_instance=' do
    subject(:write_metasploit_instance) do
      command_dispatcher.metasploit_instance = metasploit_instance
    end

    #
    # lets
    #

    let(:metasploit_class) do
      Class.new(Msf::Module)
    end

    let(:metasploit_instance) do
      metasploit_class.new
    end

    let(:module_class) do
      FactoryGirl.create(:mdm_module_class)
    end

    #
    # Callbacks
    #

    before(:each) do
      stub_const('MetasploitClass', metasploit_class)
      metasploit_class.stub(module_class: module_class)
    end

    context 'with #metasploit_instance' do
      #
      # lets
      #

      let(:metasploit_class_was) do
        Class.new(Msf::Module)
      end

      let(:metasploit_instance_was) do
        metasploit_class_was.new
      end

      let(:module_class_was) do
        FactoryGirl.create(:mdm_module_class)
      end

      #
      # Callbacks
      #

      before(:each) do
        stub_const('MetasploitClassWas', metasploit_class_was)
        metasploit_class_was.stub(module_class: module_class_was)

        msf_ui_console_driver.metasploit_instance = metasploit_instance_was
      end

      it 'stores copy of #metasploit_instance #datastore in #data_store_by_module_class_full_name' do
        write_metasploit_instance
        data_store = command_dispatcher.data_store_by_module_class_full_name[module_class_was.full_name]

        expect(data_store).to eq(metasploit_instance_was.datastore)
      end

      it 'caches full name for use with previous' do
        expect {
          write_metasploit_instance
        }.to change {
          command_dispatcher.instance_variable_get :@module_class_full_name_was
        }.to(module_class_was.full_name)
      end
    end

    context 'without #metasploit_instance' do
      it 'sets #driver #metasploit_instance' do
        expect(msf_ui_console_driver).to receive(:metasploit_instance=).with(metasploit_instance)

        write_metasploit_instance
      end

      it 'resets payload cache' do
        to_be_cleared = double('@cache_payloads')
        command_dispatcher.instance_variable_set :@cache_payloads, to_be_cleared

        expect {
          write_metasploit_instance
        }.to change {
          command_dispatcher.instance_variable_get :@cache_payloads
        }.from(
                 to_be_cleared
             ).to(
                 nil
             )
      end

      context 'with metasploit_instance' do
        context 'with cached data store' do
          let(:cached_data_store) do
            Msf::DataStore.new.tap { |data_store|
              data_store['CACHED_KEY'] = 'CACHED_VALUE'
            }
          end

          before(:each) do
            command_dispatcher.data_store_by_module_class_full_name[module_class.full_name] = cached_data_store
          end

          it 'updates metasploit_instance datastore with cache' do
            write_metasploit_instance

            cached_data_store.each do |key, value|
              expect(metasploit_instance.datastore[key]).to eq(value)
            end
          end
        end
      end

      context 'without metasploit_instance' do
        let(:metasploit_instance) do
          nil
        end

        it { should be_nil }
      end
    end
  end
end
