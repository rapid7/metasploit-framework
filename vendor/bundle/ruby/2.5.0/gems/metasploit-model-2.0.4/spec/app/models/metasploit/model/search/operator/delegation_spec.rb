RSpec.describe Metasploit::Model::Search::Operator::Delegation, type: :model do
  subject(:operator) do
    described_class.new(
        :klass => klass
    )
  end

  let(:klass) do
    Class.new
  end

  it { is_expected.to be_a Metasploit::Model::Search::Operator::Base }

  context 'operator_name' do
    subject(:operator_name) do
      subclass.operator_name
    end

    let(:subclass) do
      Class.new(described_class)
    end

    context 'with namespace' do
      let(:base_name) do
        'Demodulized'
      end

      before(:example) do
        stub_const("Namespace::#{base_name}", subclass)
      end

      it 'should remove namespace' do
        expect(operator_name).to eq(base_name.downcase.to_sym)
      end
    end

    context 'with Camelized' do
      before(:example) do
        stub_const("CamelCase", subclass)
      end

      it 'should convert name to underscore' do
        expect(operator_name).to eq(:camel_case)
      end
    end
  end

  context '#operator' do
    subject(:named_operator) do
      operator.send(:operator, formatted_operator)
    end

    let(:formatted_operator) do
      double('Formatted Operator', :to_sym => :formatted_operator)
    end

    let(:search_operator) do
      double('Search Operator')
    end

    let(:search_operator_by_name) do
      {
          formatted_operator.to_sym => search_operator
      }
    end

    before(:example) do
      outer_search_operator_by_name = search_operator_by_name

      klass.send(:define_singleton_method, :search_operator_by_name) do
        outer_search_operator_by_name
      end
    end

    it 'should convert formatted_operator to Symbol' do
      expect(formatted_operator).to receive(:to_sym)

      named_operator
    end

    it 'should look up operator name in search_operator_by_name of #klass' do
      expect(named_operator).to eq(search_operator)
    end

    context 'with name not in klass.search_operator_by_name' do
      let(:search_operator_by_name) do
        {}
      end

      it 'should raise ArgumentError' do
        expect {
          named_operator
        }.to raise_error(ArgumentError, "No operator with name #{formatted_operator.to_sym.inspect} on #{klass}")
      end
    end
  end

  context '#name' do
    subject(:name) do
      operator.name
    end

    it 'should delegate to operator_name' do
      operator_name = double('Operator Name')
      allow(operator.class).to receive(:operator_name).and_return(operator_name)

      expect(name).to eq(operator_name)
    end
  end
end