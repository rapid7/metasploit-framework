RSpec.describe MetasploitDataModels::Search::Operator::IPAddress, type: :model do
  subject(:operator) {
    described_class.new
  }

  context '#operate_on' do
    subject(:operate_on) {
      operator.operate_on(formatted_value)
    }

    let(:formatted_value) {
      nil
    }

    it { is_expected.to be_a MetasploitDataModels::Search::Operation::IPAddress }
  end
end