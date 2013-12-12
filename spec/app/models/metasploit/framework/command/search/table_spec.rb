require 'spec_helper'

describe Metasploit::Framework::Command::Search::Table do
  include_context 'Msf::Ui::Console::Driver'

  subject(:command) do
    described_class.new(
        parent: parent
    )
  end

  let(:dispatcher) do
    Msf::Ui::Console::CommandDispatcher::Core.new(msf_ui_console_driver)
  end

  let(:parent) do
    Metasploit::Framework::Command::Search.new(
        dispatcher: dispatcher
    )
  end

  it_should_behave_like 'Metasploit::Framework::Command::Child'
  it_should_behave_like 'Metasploit::Framework::Command::Search::Table::Columns'
  it_should_behave_like 'Metasploit::Framework::Command::Search::Table::TabCompletion'
  it_should_behave_like 'Metasploit::Framework::Command::Search::Table::ValidationErrors'

  context 'validations' do
    context 'visitor' do
      subject(:visitor_valid) do
        command.send(:visitor_valid)
      end

      let(:visitor) do
        command.visitor
      end

      it 'should recursively validate #visitor' do
        visitor.should_receive(:valid?).and_return(true)

        visitor_valid
      end

      context 'with valid' do
        before(:each) do
          visitor.stub(valid?: true)
        end

        it 'should not add error on #visitor' do
          visitor_valid

          command.errors[:visitor].should be_empty
        end
      end

      context 'without valid' do
        #
        # lets
        #

        let(:error) do
          I18n.translate!(:'errors.messages.invalid')
        end

        #
        # callbacks
        #
        before(:each) do
          visitor.stub(valid?: false)
        end

        it 'should add :invalid error on #visitor' do
          visitor_valid

          command.errors[:visitor].should include(error)
        end
      end
    end
  end

  context '#formatted_operations' do
    subject(:formatted_operations) do
      command.formatted_operations
    end

    context 'default' do
      it { should == [] }
    end

    context 'writer' do
      let(:expected) do
        double('#formatted_operations')
      end

      #
      # callbacks
      #

      before(:each) do
        command.formatted_operations = expected
      end

      it 'should be written value' do
        formatted_operations.should == expected
      end
    end
  end

  context '#query' do
    subject(:query) do
      command.query
    end

    it { should be_a Metasploit::Model::Search::Query }

    its(:klass) { should == Mdm::Module::Instance }

    context 'formatted_operations' do
      subject(:formatted_operations) do
        query.formatted_operations
      end

      it 'should be #formatted_operations' do
        formatted_operations.should == query.formatted_operations
      end
    end
  end

  context '#run_with_valid' do
    include_context 'output'

    subject(:run_with_valid) do
      command.send(:run_with_valid)
    end

    let(:command) do
      described_class.new(
          formatted_operations: formatted_operations,
          parent: parent
      )
    end

    let(:formatted_operations) do
      [
          # chosen arbitrarily as a valid operation
          "module_class.module_type:#{module_type}"
      ]
    end

    let(:module_type) do
      FactoryGirl.generate :metasploit_model_module_type
    end

    it 'should set TablePrint::Config.max_width to current shell width' do
      TablePrint::Config.should_receive(:max_width=).and_call_original

      quietly
    end

    it 'should create a TablePrint::Printer with #visitor visit and #column_name_set as an Array' do
      TablePrint::Printer.should_receive(:new).with(
          command.visitor.visit,
          command.column_name_set.to_a
      ).and_call_original

      quietly
    end

    it 'should print table' do
      printed_table = 'printed table'
      TablePrint::Printer.any_instance.should_receive(:table_print).and_return(printed_table)
      command.should_receive(:print_line).with(printed_table)

      quietly
    end
  end

  context '#visitor' do
    subject(:visitor) do
      command.visitor
    end

    it { should be_a MetasploitDataModels::Search::Visitor::Relation }

    context 'query' do
      subject(:query) do
        visitor.query
      end

      it 'should be #query' do
        query.should == command.query
      end
    end
  end
end