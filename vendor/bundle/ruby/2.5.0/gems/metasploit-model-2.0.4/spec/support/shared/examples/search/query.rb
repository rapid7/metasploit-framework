RSpec.shared_examples_for 'search query' do |options={}|
  options.assert_valid_keys(:formatted_operator)

  formatted_operator = options.fetch(:formatted_operator)

  context "with #{formatted_operator}" do
    subject(:query) do
      Metasploit::Model::Search::Query.new(
          :formatted => formatted,
          :klass => base_class
      )
    end

    let(:formatted) do
      "#{formatted_operator}:\"#{formatted_value}\""
    end

    let(:formatted_value) do
      "formatted_value"
    end

    context 'operations' do
      subject(:operations) do
        query.operations
      end

      context 'operator with matching name' do
        subject(:operator) do
          operation.operator
        end

        let(:operation) do
          operations.find { |operation|
            operation.operator.name == formatted_operator.to_sym
          }
        end

        it { is_expected.not_to be_nil }
        it { is_expected.to be_valid }
      end
    end
  end
end