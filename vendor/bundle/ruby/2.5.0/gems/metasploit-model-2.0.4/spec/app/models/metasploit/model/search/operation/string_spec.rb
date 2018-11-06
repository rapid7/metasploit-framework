RSpec.describe Metasploit::Model::Search::Operation::String, type: :model do
  context 'validation' do
    it { is_expected.to validate_presence_of(:value) }
  end

  it_should_behave_like 'Metasploit::Model::Search::Operation::Value::String'
end