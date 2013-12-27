require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/command_dispatcher/auxiliary'

describe Msf::Ui::Console::CommandDispatcher::Auxiliary do
  include_context 'metasploit_super_class_by_module_type'
  include_context 'Msf::DBManager'
  include_context 'Msf::Ui::Console::Driver'

  subject(:command_dispatcher) do
    described_class.new(msf_ui_console_driver)
  end

  let(:metasploit_class) do
    Class.new(metasploit_super_class)
  end

  let(:metasploit_instance) do
    metasploit_class.new
  end

  let(:module_type) do
    'auxiliary'
  end

  #
  # Callbacks
  #

  before(:each) do
    allow(msf_ui_console_driver).to receive(:metasploit_instance).and_return(metasploit_instance)
  end

  it_should_behave_like 'Msf::Ui::Console::ModuleCommandDispatcher'

  context '#cmd_check' do
    subject(:cmd_check) do
      command_dispatcher.cmd_check
    end

    context 'with driver.metasploit_instance.cmd_check' do
      #
      # lets
      #

      let(:metasploit_instance_cmd_check) do
        double('#driver #metasploit_instance #cmd_check')
      end

      #
      # Callbacks
      #

      before(:each) do
        allow(metasploit_instance).to receive(:cmd_check).and_return(metasploit_instance_cmd_check)
      end

      it 'delegates to driver.metasploit_intance.cmd_check' do
        expect(cmd_check).to eq(metasploit_instance_cmd_check)
      end
    end

    context 'without driver.metasploit_instance.cmd_check' do
      specify {
        expect {
        cmd_check
        }.to raise_error(NoMethodError)
      }
    end
  end

  context '#commands' do
    subject(:commands) do
      command_dispatcher.commands
    end

    its(['run']) { should == 'Launches the auxiliary module' }
    its(['rerun']) { should == 'Reloads and launches the auxiliary module' }
    its(['exploit']) { should == 'This is an alias for the run command' }
    its(['rexploit']) { should == 'This is an alias for the rerun command' }

    context 'with metasploit_instance' do
      before(:each) do
        allow(metasploit_instance).to receive(:auxiliary_commands).and_return(auxiliary_commands)
      end

      context 'with auxiliary_commands' do
        let(:auxiliary_commands) do
          {
              'check' => 'Check if the target is vulnerable'
          }
        end

        it 'includes the auxiliary commands of the metasploit instance' do
          expect(commands).to include(auxiliary_commands)
        end
      end
    end
  end

  context '#name' do
    subject(:name) do
      command_dispatcher.name
    end

    it { should == 'Auxiliary' }
  end

  context '#method_missing and #respond_to_missing?' do
    subject(:missing_method) do
      command_dispatcher.send(method_name, *arguments, &block)
    end

    #
    # lets
    #

    let(:arguments) do
      []
    end

    let(:block) do
      nil
    end

    let(:method_name) do
      :missing_method
    end

    #
    # Callbacks
    #

    context 'with driver.metasploit_instance responds to method_name' do
      #
      # lets
      #

      let(:metasploit_instance_return) do
        double("#driver #metasploit_instance #{method_name}")
      end

      #
      # Callbacks
      #

      before(:each) do
        metasploit_instance_return = self.metasploit_instance_return

        metasploit_instance.define_singleton_method(method_name) do
          metasploit_instance_return
        end
      end

      it 'delegates to driver.metasploit_instance' do
        expect(missing_method).to eq(metasploit_instance_return)
      end

      it 'responds to the method' do
        expect(command_dispatcher).to respond_to(method_name)
      end

      it 'allows method to be picked off of driver.metasploit_instance with #method which indicates the #responds_to_missing? is defined correctly' do
        expect {
          command_dispatcher.method(method_name)
        }.not_to raise_error
      end
    end

    context 'with driver.metasploit_instance does not respond to method_name' do
      specify {
        expect {
          missing_method
        }.to raise_error(NameError)
      }

      it 'does not respond to the method' do
        expect(command_dispatcher).not_to respond_to(method_name)
      end
    end
  end
end
