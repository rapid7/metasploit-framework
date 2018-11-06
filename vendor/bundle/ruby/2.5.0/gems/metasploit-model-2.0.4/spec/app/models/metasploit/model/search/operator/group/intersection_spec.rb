RSpec.describe Metasploit::Model::Search::Operator::Group::Intersection, type: :model do
  it { is_expected.to be_a Metasploit::Model::Search::Operator::Group::Base }

  context 'operation_class_name' do
    subject(:operation_class_name) {
      described_class.operation_class_name
    }

    it { is_expected.to eq('Metasploit::Model::Search::Operation::Group::Intersection') }
  end
end