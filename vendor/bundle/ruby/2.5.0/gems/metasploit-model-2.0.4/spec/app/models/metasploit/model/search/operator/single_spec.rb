RSpec.describe Metasploit::Model::Search::Operator::Single, type: :model do
  subject(:operator) do
    described_class.new
  end

  it { is_expected.to be_a Metasploit::Model::Search::Operator::Base }

  context 'CONSTANTS' do
    context 'MODULE_SEPARATOR' do
      subject(:module_separator) do
        described_class::MODULE_SEPARATOR
      end

      it { is_expected.to eq('::') }
    end

    context 'OPERATION_NAMESPACE_NAME' do
      subject(:operation_namespace_name) do
        described_class::OPERATION_NAMESPACE_NAME
      end

      it { is_expected.to eq('Metasploit::Model::Search::Operation') }
    end
  end

  context 'constant_name' do
    subject(:constant_name) do
      described_class.constant_name(type)
    end

    context 'with Hash' do
      context 'with zero entries' do
        let(:type) do
          {}
        end

        specify {
          expect {
            constant_name
          }.to raise_error(ArgumentError, "Cannot destructure a Hash without entries")
        }
      end

      context 'with one entry' do
        let(:key) do
          :enum
        end

        let(:key_constant_name) do
          'Enum'
        end

        let(:type) do
          {
              key => value
          }
        end

        let(:value) do
          :integer
        end

        let(:value_constant_name) do
          'Integer'
        end

        it 'should be the constant_name of the key and value separated by MODULE_SEPARATOR' do
          expect(constant_name).to eq("#{key_constant_name}#{described_class::MODULE_SEPARATOR}#{value_constant_name}")
        end
      end

      context 'with multiple entries' do
        let(:type) do
          {
              key1: :value1,
              key2: :value2
          }
        end

        specify {
          expect {
            constant_name
          }.to raise_error(ArgumentError, 'Cannot destructure a Hash with multiple entries')
        }
      end
    end

    context 'with Symbol' do
      let(:type) do
        :integer
      end

      it 'should constantize string version of Symbol' do
        expect(constant_name).to eq('Integer')
      end
    end

    context 'without Hash or Symbol' do
      let(:type) do
        nil
      end

      specify {
        expect {
          constant_name
        }.to raise_error(ArgumentError, "Can only convert Hashes and Symbols to constant names, not #{type.inspect}")
      }
    end
  end

  context '#operate_on' do
    subject(:operate_on) do
      operator.operate_on(formatted_value)
    end

    let(:formatted_value) do
      'value'
    end

    let(:operation_class) do
      double('Operation Class')
    end

    before(:example) do
      allow(operator).to receive(:operation_class).and_return(operation_class)
    end

    it 'should call new on #operation_class' do
      expect(operation_class).to receive(:new).with(:value => formatted_value, :operator => operator)

      operate_on
    end

    it 'should return instance of #operation_class' do
      operation = double('Operation')
      allow(operation_class).to receive(:new).and_return(operation)

      expect(operate_on).to eq(operation)
    end
  end

  context "#operation_class" do
    subject(:operation_class) do
      operator.send(:operation_class)
    end

    before(:example) do
      allow(operator).to receive(:type).and_return(type)
    end

    context 'type' do
      context 'with :boolean' do
        let(:type) do
          :boolean
        end

        it { is_expected.to eq(Metasploit::Model::Search::Operation::Boolean) }
      end

      context 'with :date' do
        let(:type) do
          :date
        end

        it { is_expected.to eq(Metasploit::Model::Search::Operation::Date) }
      end

      context 'with set: :integer' do
        let(:type) do
          {
              set: :integer
          }
        end

        it { is_expected.to eq(Metasploit::Model::Search::Operation::Set::Integer) }
      end

      context 'with set: :string' do
        let(:type) do
          {
              set: :string
          }
        end

        it { is_expected.to eq(Metasploit::Model::Search::Operation::Set::String) }
      end

      context 'with :integer' do
        let(:type) do
          :integer
        end

        it { is_expected.to eq(Metasploit::Model::Search::Operation::Integer) }
      end

      context 'with :string' do
        let(:type) do
          :string
        end

        it { is_expected.to eq(Metasploit::Model::Search::Operation::String) }
      end

      context 'with nil' do
        let(:name) do
          :single
        end

        let(:type) do
          nil
        end

        before(:example) do
          allow(operator).to receive(:name).and_return(name)
        end

        it 'should raise ArgumentError' do
          expect {
            operation_class
          }.to raise_error(
                   ArgumentError,
                   "#{described_class}#operation_class_name cannot be derived for #{name} operator because its type is nil")
        end
      end
    end
  end

  context '#operation_class_name' do
    subject(:operation_class_name) do
      operator.send(:operation_class_name)
    end

    before(:example) do
      allow(operator).to receive(:type).and_return(type)
    end

    context 'type' do
      context 'with :boolean' do
        let(:type) do
          :boolean
        end

        it { is_expected.to eq('Metasploit::Model::Search::Operation::Boolean') }
      end

      context 'with :date' do
        let(:type) do
          :date
        end

        it { is_expected.to eq('Metasploit::Model::Search::Operation::Date') }
      end

      context 'with set: :integer' do
        let(:type) do
          {
              set: :integer
          }
        end

        it { is_expected.to eq('Metasploit::Model::Search::Operation::Set::Integer') }
      end

      context 'with set: :string' do
        let(:type) do
          {
              set: :string
          }
        end

        it { is_expected.to eq('Metasploit::Model::Search::Operation::Set::String') }
      end

      context 'with :integer' do
        let(:type) do
          :integer
        end

        it { is_expected.to eq('Metasploit::Model::Search::Operation::Integer') }
      end

      context 'with :string' do
        let(:type) do
          :string
        end

        it { is_expected.to eq('Metasploit::Model::Search::Operation::String') }
      end

      context 'with nil' do
        let(:name) do
          :single
        end

        let(:type) do
          nil
        end

        before(:example) do
          allow(operator).to receive(:name).and_return(name)
        end

        it 'should raise ArgumentError' do
          expect {
            operation_class_name
          }.to raise_error(
                   ArgumentError,
                   "#{described_class}#operation_class_name cannot be derived for #{name} operator because its type is nil")
        end
      end
    end
  end

  context '#type' do
    subject(:type) do
      operator.type
    end

    it 'should not be implemented' do
      expect {
        type
      }.to raise_error(NotImplementedError)
    end
  end
end