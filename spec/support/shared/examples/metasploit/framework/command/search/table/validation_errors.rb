shared_examples_for 'Metasploit::Framework::Command::Search::Table::ValidationErrors' do
  include_context 'output'

  context '#print_operation_validation_errors' do
    subject(:print_operation_validation_errors) do
      command.send(:print_operation_validation_errors, operation)
    end

    let(:operation) do
      Metasploit::Model::Search::Operation::Base.new(
          operator: operator
      )
    end

    context 'with operator' do
      let(:operator) do
        Mdm::Module::Instance.search_operator_by_name.values.sample
      end

      it 'should use <name>:<value> as context for operation errors' do
        command.should_receive(:print_indented_validation_errors_with_context).with(
            operation,
            hash_including(
                context: "#{operator.name}:#{operation.value}",
                depth: 0
            )
        ).ordered
        command.should_receive(:print_indented_validation_errors_with_context).ordered

        quietly
      end

      it 'should print operator errors' do
        command.should_receive(:print_indented_validation_errors_with_context).ordered
        command.should_receive(:print_indented_validation_errors_with_context).with(
            operator,
            hash_including(
                context: operator.name,
                depth: 1
            )
        ).ordered

        quietly
      end
    end

    context 'without operator' do
      let(:operator) do
        nil
      end

      it 'should use :<value> as context for operation errors' do
        command.should_receive(:print_indented_validation_errors_with_context).with(
            operation,
            hash_including(
                context: ":#{operation.value}"
            )
        )

        quietly
      end
    end

    context 'responds to :children' do
      let(:operation) do
        Metasploit::Model::Search::Operation::Union.new(
            children: children
        )
      end

      context 'with children' do
        def child_operator
          Mdm::Module::Instance.search_operator_by_name.values.sample
        end

        let(:child_operators) do
          Array.new(2) {
            child_operator
          }
        end

        let(:children) do
          child_operators.collect { |child_operator|
            Metasploit::Model::Search::Operation::Base.new(
                operator: child_operator
            )
          }
        end

        it 'should recursively print operation validation errors' do
          command.should_receive(:print_operation_validation_errors).with(operation).and_call_original

          children.each do |child|
            command.should_receive(:print_operation_validation_errors).with(
                child,
                hash_including(
                    depth: 1
                )
            )
          end

          quietly
        end
      end
    end
  end

  context '#print_query_errors' do
    subject(:print_query_errors) do
      command.send(:print_query_errors, options)
    end

    #
    # lets
    #

    let(:options) do
      {}
    end

    let(:query) do
      command.query
    end

    #
    # callbacks
    #

    before(:each) do
      command.query.valid?
    end

    it 'should default to a depth of 0' do
      command.should_receive(:print_indented_error).with(
          anything,
          hash_including(
              depth: 0
          )
      )

      quietly
    end

    it 'should print full messages for each error' do
      # need to test in pieces as if running in a TTY, then '[-]' will be surrounded by ANSI escape sequences to produce
      # the red color
      output.should include "[-]"
      output.should include "Operations is too short (minimum is 1 operation)"
    end

    context 'with operations' do
      let(:command) do
        described_class.new(
            formatted_operations: formatted_operations,
            parent: parent
        )
      end

      let(:formatted_operations) do
        [
            'invalid_operator1:invalid_value1',
            'invalid_operator2:invalid_value2'
        ]
      end

      it 'should have operations' do
        query.operations.should_not be_empty
      end

      it 'should print operation validation errors for each operation' do
        query.operations.each do |operation|
          command.should_receive(:print_operation_validation_errors).with(
              operation,
              an_instance_of(Hash)
          )
        end

        quietly
      end

      context 'with non-default :depth' do
        let(:depth) do
          1
        end

        let(:options) do
          {
              depth: depth
          }
        end

        it 'should print operation validation errors at deeper depth' do
          command.should_receive(:print_indented_error).with(
              anything,
              hash_including(
                  depth: depth
              )
          )

          operations_depth = depth + 1

          query.operations.each do |operation|
            command.should_receive(:print_operation_validation_errors).with(
                anything,
                hash_including(
                    depth: operations_depth
                )
            )
          end

          quietly
        end
      end
    end
  end

  context '#print_validation_errors' do
    subject(:print_validation_errors) do
      command.send(:print_validation_errors)
    end

    it 'should call #print_visitor_validation_errors' do
      command.should_receive(:print_visitor_validation_errors)

      quietly
    end
  end

  context '#print_indented_validation_errors_with_context' do
    subject(:print_indented_validation_errors_with_context) do
      command.send(
          :print_indented_validation_errors_with_context,
          model,
          options
      )
    end

    let(:context) do
      'the model'
    end

    let(:model) do
      model_class.new
    end

    let(:model_class) do
      Class.new do
        include ActiveModel::Validations
      end
    end

    let(:options) do
      {
          context: context
      }
    end

    context 'with errors' do
      #
      # lets
      #

      let(:attribute) do
        :the_attribute
      end

      let(:error) do
        'is invalid'
      end

      #
      # Callbacks
      #

      before(:each) do
        stub_const('Model', model_class)

        model.errors[attribute] << error
      end

      it 'should print error indented prefixed by context' do
        command.should_receive(:print_indented_error) do |string|
          string.should == "#{context} - #{attribute.to_s.humanize} #{error}"
        end

        quietly
      end

      context 'with :depth' do
        let(:depth) do
          1
        end

        let(:options) do
          super().merge(
              depth: depth
          )
        end

        it 'should print error at :depth' do
          command.should_receive(:print_indented_error).with(
              anything,
              hash_including(depth: depth)
          )

          quietly
        end
      end

      context 'without :depth' do
        it 'should print error at depth 0' do
          command.should_receive(:print_indented_error).with(
              anything,
              hash_including(depth: 0)
          )

          quietly
        end
      end
    end

    context 'without errors' do
      it 'should print nothing' do
        output.should be_empty
      end
    end
  end

  context '#print_visitor_validation_errors' do
    subject(:print_visitor_validation_errors) do
      command.send(:print_visitor_validation_errors)
    end

    it 'should call #print_query_errors' do
      command.should_receive(:print_query_errors)

      quietly
    end

    context 'with visitor errors' do
      #
      # lets
      #

      let(:visitor) do
        command.visitor
      end

      #
      # Callbacks
      #

      before(:each) do
        command.valid?
      end

      it 'should print full messages as errors' do
        visitor.errors.should_not be_empty

        visitor.errors.full_messages.each do |full_message|
          command.should_receive(:print_error).with(full_message)
        end

        # clear errors from query so #print_query_errors doesn't print anything, which would interfere with above
        # should_receive(:print_error)
        visitor.query.errors.clear

        quietly
      end
    end
  end
end