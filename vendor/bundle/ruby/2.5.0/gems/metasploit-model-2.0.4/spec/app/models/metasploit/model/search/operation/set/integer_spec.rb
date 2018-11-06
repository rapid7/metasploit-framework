RSpec.describe Metasploit::Model::Search::Operation::Set::Integer, type: :model do
  it { is_expected.to be_a Metasploit::Model::Search::Operation::Set }

  it_should_behave_like 'Metasploit::Model::Search::Operation::Value::Integer'
end