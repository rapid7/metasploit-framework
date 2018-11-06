RSpec.describe Metasploit::Model::Search::Operator::Attribute, type: :model do
  it { is_expected.to be_a Metasploit::Model::Search::Operator::Single }

  context 'CONSTANTS' do
    context 'TYPES' do
      subject(:types) do
        described_class::TYPES
      end

      it { is_expected.to include(:boolean) }
      it { is_expected.to include(:date) }
      it {
        is_expected.to include(
                   {
                       set: :integer
                   }
               )
      }
      it {
        is_expected.to include(
                   {
                       set: :string
                   }
               )
      }
      it { is_expected.to include(:integer) }
      it { is_expected.to include(:string) }
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of(:attribute) }
    it { is_expected.to validate_inclusion_of(:type).in_array(described_class::TYPES) }
  end

  context '#attribute_enumerable' do
    subject(:attribute_set) do
      attribute_operator.attribute_set
    end

    let(:attribute) do
      :set_attribute
    end

    let(:attribute_operator) do
      described_class.new(
          attribute: attribute,
          klass: klass
      )
    end

    let(:expected_attribute_set) do
      Set.new [:a, :b]
    end

    let(:klass) do
      Class.new.tap { |klass|
        expected_attribute_set = self.expected_attribute_set

        klass.define_singleton_method("#{attribute}_set") do
          expected_attribute_set
        end
      }
    end

    context 'with responds to #attribute_set_method_name' do
      let(:expected_attribute_set) do
        Set.new(
            [
                :a,
                :b,
                :c
            ]
        )
      end

      it 'should be #klass #<attribute>_set' do
        expect(attribute_set).to eq(expected_attribute_set)
      end
    end
  end

  context '#name' do
    subject(:name) do
      attribute_operator.name
    end

    let(:attribute) do
      FactoryGirl.generate :metasploit_model_search_operator_attribute_attribute
    end

    let(:attribute_operator) do
      described_class.new(
          :attribute => attribute
      )
    end

    it 'should be #attribute' do
      expect(name).to eq(attribute)
    end
  end
end
