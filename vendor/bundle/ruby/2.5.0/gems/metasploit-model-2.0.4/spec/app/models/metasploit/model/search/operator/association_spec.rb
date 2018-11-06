RSpec.describe Metasploit::Model::Search::Operator::Association, type: :model do
  subject(:operator) do
    described_class.new(
        :association => association,
        :source_operator => source_operator
    )
  end

  let(:association) do
    FactoryGirl.generate :metasploit_model_search_operator_association_association
  end

  let(:source_operator) do
    double('Metasploit::Model::Search::Operator::Base')
  end

  it { is_expected.to be_a Metasploit::Model::Search::Operator::Base }

  context 'validations' do
    it { is_expected.to validate_presence_of(:association) }
    it { is_expected.to validate_presence_of(:source_operator) }
  end

  context '#help' do
    subject(:help) do
      operator.help
    end

    it 'should delegate to #source_operator' do
      expect(source_operator).to receive(:help)

      help
    end
  end

  context '#name' do
    subject(:name) do
      operator.name
    end

    let(:source_operator) {
      double(
          'Metasploit::Model::Search::Operator::Base',
          name: source_operator_name
      )
    }

    let(:source_operator_name) {
      'source_operator_name'
    }

    it { is_expected.to be_a Symbol }

    it 'should be <association>.<source_operator.name>' do
      expect(name).to eq :"#{association}.#{source_operator_name}"
    end
  end

  context '#operate_on' do
    subject(:operate_on) {
      operator.operate_on(formatted_value)
    }

    #
    # lets
    #

    let(:expected_source_operation) {
      double('source operation')
    }

    let(:formatted_value) {
      'formatted-value'
    }

    let(:source_operator) {
      super().tap { |source_operator|
        expect(source_operator).to receive(:operate_on).with(formatted_value).and_return(expected_source_operation)
      }
    }

    it { is_expected.to be_a Metasploit::Model::Search::Operation::Association }

    context 'Metasploit::Model::Search::Operation::Association' do
      context '#operator' do
        subject(:operation_operator) {
          operate_on.operator
        }

        it 'is this association operator' do
          expect(operation_operator).to eq(operator)
        end
      end

      context '#source_operation' do
        subject(:source_operation) {
          operate_on.source_operation
        }

        it 'is operation from Metasploit::Model::Search::Operator::Association#source_operator' do
          expect(source_operation).to eq(expected_source_operation)
        end
      end
    end
  end
end