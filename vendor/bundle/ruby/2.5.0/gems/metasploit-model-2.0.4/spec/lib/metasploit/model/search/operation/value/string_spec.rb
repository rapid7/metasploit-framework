RSpec.describe Metasploit::Model::Search::Operation::Value::String do
  it_should_behave_like 'Metasploit::Model::Search::Operation::Value::String' do
    let(:operation_class) do
      described_class = self.described_class

      Class.new(Metasploit::Model::Base) do
        include described_class

        #
        # Attributes
        #

        # @!attribute [rw] value
        attr_reader :value
      end
    end
  end
end