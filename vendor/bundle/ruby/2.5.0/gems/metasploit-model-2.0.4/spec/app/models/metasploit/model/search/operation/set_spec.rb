RSpec.describe Metasploit::Model::Search::Operation::Set, type: :model do
  subject(:set) do
    described_class.new(
        operator: operator,
        value: value
    )
  end

  context 'validations' do
    context 'value' do
      subject(:value_errors) do
        set.errors[:value]
      end

      before(:example) do
        set.valid?
      end

      context 'membership' do
        let(:attribute) do
          :enumerable_attribute
        end

        let(:attribute_set) do
          klass.send("#{attribute}_set")
        end

        let(:human_attribute_set) do
          "{#{attribute_set.sort.map(&:inspect).join(", ")}}"
        end

        let(:error) do
          I18n.translate(
              'metasploit.model.errors.models.metasploit/model/search/operation/set.attributes.value.inclusion',
              set: human_attribute_set
          )
        end

        let(:klass) do
          attribute = self.attribute
          type = self.type

          Class.new(Metasploit::Model::Base) do
            include Metasploit::Model::Search

            #
            # Search Attributes
            #

            search_attribute attribute, type: type

            #
            # Methods
            #

            # List of valid values for attribute.
            #
            # @return [Array]
            define_singleton_method("#{attribute}_set") do
              [
                  :a,
                  :b,
                  :c
              ]
            end
          end
        end

        let(:type) do
          types.sample
        end

        let(:types) do
          [
              {
                  set: :integer
              },
              {
                  set: :string
              }
          ]
        end

        context 'with operator' do
          let(:operator) do
            Metasploit::Model::Search::Operator::Attribute.new(
                attribute: attribute,
                klass: klass,
                type: type
            )
          end

          context 'with value in attribute_set' do
            let(:value) do
              attribute_set.sample
            end

            it { is_expected.not_to include(error) }
          end

          context 'without value in attribute_set' do
            let(:value) do
              :not_an_member
            end

            it { is_expected.to include(error) }
          end
        end

        context 'without operator' do
          let(:operator) do
            nil
          end

          let(:value) do
            nil
          end

          it { is_expected.not_to include(error) }
        end
      end
    end
  end
end