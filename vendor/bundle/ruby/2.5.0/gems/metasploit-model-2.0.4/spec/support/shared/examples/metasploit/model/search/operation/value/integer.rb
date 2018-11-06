RSpec.shared_examples_for 'Metasploit::Model::Search::Operation::Value::Integer' do
  let(:operation_class) do
    described_class
  end

  context '#class' do
    subject do
      operation_class
    end

    it { is_expected.to include Metasploit::Model::Search::Operation::Value::Integer }
  end

  context '#value' do
    subject(:value) do
      operation.value
    end

    let(:operation) do
      operation_class.new(:value => formatted_value)
    end

    context 'with Integer' do
      let(:formatted_value) do
        1
      end

      it 'should pass through Integer' do
        expect(value).to eq(formatted_value)
      end
    end

    context 'with Integer#to_s' do
      let(:formatted_value) do
        integer.to_s
      end

      let(:integer) do
        1
      end

      it 'should convert String to Integer' do
        expect(value).to eq(integer)
      end
    end

    context 'with mix text and numerals' do
      let(:formatted_value) do
        "#{integer}mix"
      end

      let(:integer) do
        123
      end

      it 'should not extract the number' do
        expect(value).not_to eq(integer)
      end

      it 'should pass through the full value' do
        expect(value).to eq(formatted_value)
      end
    end

    context 'with Float' do
      let(:formatted_value) do
        0.1
      end

      it 'should not truncate Float to Integer' do
        expect(value).not_to eq(formatted_value.to_i)
      end

      it 'should pass through Float' do
        expect(value).to eq(formatted_value)
      end
    end
  end
end