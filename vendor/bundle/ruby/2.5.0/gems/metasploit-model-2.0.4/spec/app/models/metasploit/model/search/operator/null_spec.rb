RSpec.describe Metasploit::Model::Search::Operator::Null, type: :model do
  subject(:operator) do
    described_class.new
  end

  it { is_expected.to be_a Metasploit::Model::Search::Operator::Single }

  context 'validations' do
    context 'name' do
      let(:error) do
        I18n.translate('metasploit.model.errors.models.metasploit/model/search/operator/null.attributes.name.unknown')
      end

      before(:example) do
        operator.valid?
      end

      it 'should record error' do
        expect(operator.errors[:name]).to include(error)
      end
    end
  end

  context '#type' do
    subject(:type) do
      operator.type
    end

    it { is_expected.to be_nil }
  end

  context '#operation_class' do
    subject(:operation_class) do
      operator.send(:operation_class)
    end

    it { is_expected.to eq(Metasploit::Model::Search::Operation::Null) }
  end
end