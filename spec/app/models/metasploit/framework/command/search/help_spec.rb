require 'spec_helper'

describe Metasploit::Framework::Command::Search::Help do
  include_context 'Msf::Ui::Console::Driver'
  include_context 'output'

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

  context '#column_operators' do
    subject(:column_operators) do
      command.send(:column_operators, operators)
    end

    let(:association_and_attribute_operators) do
      Mdm::Module::Instance.search_operator_by_name.values.select { |operator|
        operator.respond_to? :attribute
      }
    end

    let(:operators) do
      association_and_attribute_operators
    end

    it 'should use Columns/Operators for section heading' do
      output.should start_with "Columns/Operators:\n"
    end

    it 'should print operators with #print_operators' do
      command.should_receive(:print_operators)

      quietly
    end

    context 'order' do
      let(:association_operator) do
        Mdm::Module::Instance.search_operator_by_name[:'actions.name']
      end

      let(:attribute_operator) do
        Mdm::Module::Instance.search_operator_by_name[:description]
      end

      let(:operators) do
        [
            attribute_operator,
            association_operator
        ]
      end

      it 'should have attribute operator with name lexicographically after association operator name' do
        name_order = attribute_operator.name <=> association_operator.name

        name_order.should == 1
      end

      it 'should have attribute operator with (association, attribute) pair before associaiton operator (association, attribute) pair' do
        attribute_operator_pair = [:'', attribute_operator.attribute]
        association_operator_pair = [association_operator.association, association_operator.attribute]
        pair_order = attribute_operator_pair <=> association_operator_pair

        pair_order.should == -1
      end

      it 'should order by (association, attribute)' do
        command.should_receive(:print_operators) do |sorted_operators|
          sorted_operators.first.should == attribute_operator
          sorted_operators.last.should == association_operator
        end

        quietly
      end
    end
  end

  context '#default_example' do
    subject(:default_example) do
      command.send(:default_example)
    end

    it 'should not contains options' do
      output.should_not match /> search.* -\S+ /
    end
  end

  context '#display_example' do
    subject(:display_example) do
      command.send(:display_example)
    end

    it 'should contain --display' do
      output.should include('--display')
    end
  end

  context '#examples' do
    subject(:examples) do
      command.send(:examples)
    end

    it 'should begin with a section heading' do
      output.should start_with "Examples:\n"
    end

    it 'should call #default_example' do
      command.should_receive(:default_example)

      quietly
    end

    it 'should call #hide_example' do
      command.should_receive(:hide_example)

      quietly
    end

    it 'should call #display_example' do
      command.should_receive(:display_example)

      quietly
    end
  end

  context '#hide_example' do
    subject(:hide_example) do
      command.send(:hide_example)
    end

    it 'should contain --hide' do
      output.should include '--hide'
    end
  end

  context '#operators' do
    subject(:operators) do
      command.send(:operators)
    end

    it 'should pass Column/Operators to #column_operators' do
      command.should_receive(:column_operators) do |column_operators|
        column_operators.all? { |operator|
          operator.respond_to? :attribute
        }.should be_true

        names = column_operators.map(&:name)

        names.should include :description
        names.should include :disclosed_on
        names.should include :license
        names.should include :name
        names.should include :privileged
        names.should include :stance
        names.should include :"actions.name"
        names.should include :"architectures.abbreviation"
        names.should include :"architectures.bits"
        names.should include :"architectures.endianness"
        names.should include :"architectures.family"
        names.should include :"authorities.abbreviation"
        names.should include :"authors.name"
        names.should include :"email_addresses.domain"
        names.should include :"email_addresses.full"
        names.should include :"email_addresses.local"
        names.should include :"module_class.full_name"
        names.should include :"module_class.module_type"
        names.should include :"module_class.payload_type"
        names.should include :"module_class.reference_name"
        names.should include :"platforms.fully_qualified_name"
        names.should include :"rank.name"
        names.should include :"rank.number"
        names.should include :"references.designation"
        names.should include :"references.url"
        names.should include :"targets.name"
      end

      quietly
    end

    it 'should pass Operators Only to #operators_only' do
      command.should_receive(:operators_only) do |only_operators|
        only_operators.none? { |operator|
          operator.respond_to? :attribute
        }.should be_true

        names = only_operators.map(&:name)

        names.should include :app
        names.should include :author
        names.should include :bid
        names.should include :cve
        names.should include :edb
        names.should include :osvdb
        names.should include :os
        names.should include :platform
        names.should include :ref
        names.should include :text
      end

      quietly
    end
  end

  context '#operators_only' do
    subject(:operators_only) do
      command.send(:operators_only, operators)
    end

    let(:operators) do
      # in reverse order to ensure sorting has to occur in method
      [
        Mdm::Module::Instance.search_operator_by_name[:edb],
        Mdm::Module::Instance.search_operator_by_name[:author]
      ]
    end

    it 'should have Operators Only as section heading' do
      output.should include "Operators Only:\n"
    end

    it 'should print operators with #print_operators' do
      command.should_receive(:print_operators)

      quietly
    end

    it 'should sort operators by name' do
      command.should_receive(:print_operators) do |sorted_operators|
        sorted_operators.should == operators.sort_by(&:name)
      end

      quietly
    end
  end

  context '#print_operators' do
    subject(:print_operators) do
      command.send(:print_operators, operators)
    end

    let(:name) do
      Mdm::Module::Instance.search_operator_by_name.keys.sample
    end

    let(:operator) do
      Mdm::Module::Instance.search_operator_by_name[name]
    end

    let(:operators) do
      [
          operator
      ]
    end

    it 'should use Metasploit::Model::Search::Operator::Base#name' do
      operator.should_receive(:name).at_least(:once).and_call_original

      quietly
    end

    it 'should use operator.help' do
      operator.should_receive(:help).and_call_original

      quietly
    end

    it 'should print at an indented dictionary list' do
      output.should == "  #{operator.name}\n    #{operator.help}\n"
    end
  end

  context '#run_with_valid' do
    subject(:run_with_valid) do
      command.send(:run_with_valid)
    end

    let(:option_parser) do
      parent.option_parser
    end

    it 'should print help from option parser' do
      option_parser.should_receive(:help)

      quietly
    end

    it 'should call #operators' do
      command.should_receive(:operators)

      quietly
    end

    it 'should call #examples' do
      command.should_receive(:examples)

      quietly
    end
  end
end