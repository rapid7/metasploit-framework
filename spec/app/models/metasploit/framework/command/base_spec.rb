require 'spec_helper'

describe Metasploit::Framework::Command::Base do
  include_context 'Msf::Ui::Console::Driver'

  subject(:command) do
    described_class.new(
        dispatcher: dispatcher
    )
  end

  #
  # Shared examples
  #

  shared_examples 'delegates to #dispatcher' do |method|
    context "##{method}" do
      subject do
        command.send(method)
      end

      it 'should delegate to #dispatcher' do
        expected = double(method)
        dispatcher.should_receive(method).and_return(expected)

        subject.should == expected
      end
    end
  end

  #
  # lets
  #

  let(:dispatcher) do
    Msf::Ui::Console::CommandDispatcher::Core.new(msf_ui_console_driver)
  end

  it_should_behave_like 'Metasploit::Framework::Command::TabCompletion'

  context 'validations' do
    it { should validate_presence_of :dispatcher }
  end

  context 'command_name' do
    subject(:command_name) do
      described_class.command_name
    end

    it { should == 'base' }
  end

  it_should_behave_like 'delegates to #dispatcher', :print_error
  it_should_behave_like 'delegates to #dispatcher', :print_good
  it_should_behave_like 'delegates to #dispatcher', :print_line
  it_should_behave_like 'delegates to #dispatcher', :print_status
  it_should_behave_like 'delegates to #dispatcher', :print_warning

  context '#print_validation_errors' do
    include_context 'output'

    subject(:print_validation_errors) do
      command.send(:print_validation_errors)
    end

    it 'should use full messages' do
      command.errors.should_receive(:full_messages).and_return([])

      quietly
    end

    context 'with errors' do
      #
      # lets
      #

      let(:attribute) do
        :the_attribute
      end

      let(:error) do
        'is filled with errors'
      end

      #
      # Callbacks
      #

      before(:each) do
        command.errors[attribute] << error
      end

      it 'should print full messages as errors' do
        command.should_receive(:print_error).with("The attribute is filled with errors")

        print_validation_errors
      end
    end
  end

  context '#run' do
    subject(:run) do
      command.run
    end

    before(:each) do
      command.stub(valid?: valid)
    end

    context 'with valid' do
      let(:valid) do
        true
      end

      it 'should call #run_with_valid' do
        command.should_receive(:run_with_valid)

        run
      end
    end

    context 'without valid' do
      let(:valid) do
        false
      end

      it 'should call #print_validation_errors' do
        command.should_receive(:print_validation_errors)

        run
      end
    end
  end

  it_should_behave_like 'delegates to #dispatcher', :width
end