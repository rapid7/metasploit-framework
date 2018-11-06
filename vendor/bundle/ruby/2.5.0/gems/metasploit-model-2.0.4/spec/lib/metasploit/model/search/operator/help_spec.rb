RSpec.describe Metasploit::Model::Search::Operator::Help do
  it_should_behave_like 'Metasploit::Model::Search::Operator::Help' do
    let(:operator) do
      operator_class.new(
          klass: klass,
          name: name
      )
    end

    let(:operator_class) do
      described_class = self.described_class

      Class.new(Metasploit::Model::Base) do
        include described_class

        #
        # Attributes
        #

        # @!attribute [rw] name
        #   Name of this operator
        #
        #   @return [String]
        attr_accessor :name

        # @!attribute [rw] klass
        #   Class being searched
        #
        #   @return [Class]
        attr_accessor :klass
      end
    end

    before(:example) do
      # operator needs to be named or mode_name will fail.
      stub_const('OperatorClass', operator_class)
    end
  end
end