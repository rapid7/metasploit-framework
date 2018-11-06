RSpec.describe Metasploit::Model::Search::With do
  let(:base_class) do
    described_class = self.described_class

    Class.new do
      include described_class
    end
  end

  context 'search_with' do
    subject(:search_with_operator) do
      base_class.search_with operator_class, options
    end

    let(:options) do
      {
          a: 1,
          b: 2
      }
    end

    let(:operator) do
      double(
          'Operator',
          :name => 'op',
          :valid! => nil
      )
    end

    let(:operator_class) do
      double(
          'Operator Class',
          :new => operator
      )
    end

    it 'should pass given options to operator_class.new' do
      expect(operator_class).to receive(:new).with(
          hash_including(options)
      ).and_return(operator)

      search_with_operator
    end

    it 'should merge :klass into options passed to operator.new' do
      expect(operator_class).to receive(:new).with(
          hash_including(
              :klass => base_class
          )
      )

      search_with_operator
    end

    it 'should validate operator' do
      allow(operator_class).to receive(:new).and_return(operator)

      expect(operator).to receive(:valid!)

      search_with_operator
    end

    it 'should add operator to search_with_operator_by_name' do
      search_with_operator

      expect(base_class.search_with_operator_by_name[operator.name]).to eq(operator)
    end
  end

  context 'search_with_operator_by_name' do
    subject(:search_with_operator_by_name) do
      base_class.search_with_operator_by_name
    end

    it 'should default to empty Hash' do
      expect(search_with_operator_by_name).to eq({})
    end
  end
end