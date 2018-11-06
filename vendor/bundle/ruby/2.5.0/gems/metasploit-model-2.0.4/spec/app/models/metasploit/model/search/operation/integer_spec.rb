RSpec.describe Metasploit::Model::Search::Operation::Integer, type: :model do
  context 'validation' do
    it { is_expected.to validate_numericality_of(:value).only_integer }
  end

  it_should_behave_like 'Metasploit::Model::Search::Operation::Value::Integer'
end