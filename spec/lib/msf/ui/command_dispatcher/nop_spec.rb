require 'spec_helper'

describe Msf::Ui::Console::CommandDispatcher::Nop do
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

  let(:module_class) do
    FactoryGirl.create(
        :mdm_module_class,
        module_type: module_type
    )
  end

  let(:module_type) do
    'nop'
  end

  #
  # Callbacks
  #

  before(:each) do
    allow(metasploit_class).to receive(:module_class).and_return(module_class)
    allow(msf_ui_console_driver).to receive(:metasploit_instance).and_return(metasploit_instance)
  end

  it_should_behave_like 'Msf::Ui::Console::ModuleCommandDispatcher'

  context '#name' do
    subject(:name) do
      command_dispatcher.name
    end

    it { should == 'Nop' }
  end
end