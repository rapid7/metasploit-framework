shared_examples_for 'Metasploit::Framework::Command::Search::Table::Columns' do
  context 'CONSTANTS' do
    context 'DEFAULT_COLUMN_NAMES' do
      subject(:default_column_names) do
        described_class::DEFAULT_COLUMN_NAMES
      end

      it { should include 'module_class.full_name' }
      it { should include 'rank.name' }
    end
  end

  context 'validations' do
    context 'column_name_set' do
      before(:each) do
        command.stub(column_name_set: column_name_set)
      end

      context 'with empty' do
        let(:column_name_set) do
          Set.new
        end

        let(:error) do
          I18n.translate!('errors.messages.blank')
        end

        it 'should add error on #column_name_set' do
          command.valid?

          command.errors[:column_name_set].should include(error)
        end
      end

      context 'without empty' do
        let(:column_name_set) do
          Set.new(['column_name'])
        end

        it 'should not add error on #column_name_set' do
          command.valid?

          command.errors[:column_name_set].should be_empty
        end
      end
    end
  end

  context '#column_name_set' do
    subject(:column_name_set) do
      command.column_name_set
    end

    let(:command) do
      described_class.new(
          formatted_operations: formatted_operations,
          parent: parent
      )
    end

    let(:formatted_operations) do
      [
          "#{operator_name}:value"
      ]
    end

    let(:operator_name) do
      Metasploit::Framework::Command::Search::Argument::Column.set.to_a.sample
    end

    context 'with hidden columns' do
      #
      # lets
      #

      let(:hidden_column_name) do
        'hidden'
      end

      let(:hidden_column) do
        Metasploit::Framework::Command::Search::Argument::Column.new(value: hidden_column_name)
      end

      #
      # Callbacks
      #

      before(:each) do
        command.hidden_columns << hidden_column
      end

      context 'with displayed_columns with same name' do
        #
        # lets
        #

        let(:displayed_column) do
          Metasploit::Framework::Command::Search::Argument::Column.new(value: hidden_column_name)
        end

        #
        # callbacks
        #

        before(:each) do
          command.displayed_columns << displayed_column
        end

        it 'should not include #hidden_column_values' do
          column_name_set.should_not include hidden_column_name
        end
      end

      context 'with #query_column_name_set with same name' do
        let(:hidden_column_name) do
          operator_name
        end

        it 'should not include #hidden_column values' do
          column_name_set.should_not include hidden_column_name
        end
      end
    end

    context 'without hidden columns' do
      it 'should include #displayed_columns values' do
        displayed_column_name_set = command.send(:displayed_column_name_set)

        displayed_column_name_set.should_not be_empty
        column_name_set.should be_superset(displayed_column_name_set)
      end

      it 'should include #query_column_name_set' do
        query_column_name_set = command.send(:query_column_name_set)

        query_column_name_set.should_not be_empty
        column_name_set.should be_superset(query_column_name_set)
      end
    end
  end

  context '#displayed_columns' do
    subject(:displayed_columns) do
      command.displayed_columns
    end

    context 'default' do
      it 'should be Array<Metasploit::Framework::Command::Search::Argument::Column>' do
        displayed_columns.should be_an Array

        displayed_columns.all? { |column|
          column.is_a? Metasploit::Framework::Command::Search::Argument::Column
        }.should be_true
      end

      it 'should include module_class.full_name' do
        displayed_columns.one? { |column|
          column.value == 'module_class.full_name'
        }.should be_true
      end

      it 'should include rank.name' do
        displayed_columns.one? { |column|
          column.value == 'rank.name'
        }.should be_true
      end
    end
  end

  context '#hidden_columns' do
    subject(:hidden_columns) do
      command.hidden_columns
    end

    context 'default' do
      it { should == [] }
    end
  end

  context '#query_column_name_set' do
    subject(:query_column_name_set) do
      command.send(:query_column_name_set)
    end

    let(:operation) do
      Metasploit::Model::Search::Operation::Base.new(
          operator: operator,
          value: value
      )
    end

    let(:operations) do
      [
          operation
      ]
    end

    let(:operator) do
      Metasploit::Model::Search::Operator::Null.new
    end

    let(:query) do
      Metasploit::Model::Search::Query.new(
          operations: operations
      )
    end

    let(:value) do
      'value'
    end

    before(:each) do
      command.stub(query: query)
    end

    it { should be_a Set }

    context 'with column name' do
      let(:name) do
        Metasploit::Framework::Command::Search::Argument::Column.set.to_a.sample
      end

      let(:operator) do
        Mdm::Module::Instance.search_operator_by_name[name.to_sym]
      end

      it 'should include operator name' do
        query_column_name_set.should include(name)
      end
    end

    context 'without column name' do
      let(:operator) do
        Metasploit::Model::Search::Operator::Attribute.new(attribute: name.to_sym)
      end

      let(:name) do
        'not_a_column'
      end

      it 'should not include operator name' do
        query_column_name_set.should_not include(name)
      end
    end
  end
end