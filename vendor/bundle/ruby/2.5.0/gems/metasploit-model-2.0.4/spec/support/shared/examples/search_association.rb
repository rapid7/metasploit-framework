RSpec.shared_examples_for 'search_association' do |association|
  context association.to_s do
    let(:association_operators) do
      base_class.search_operator_by_name.select { |_name, operator|
        operator.respond_to?(:association) and operator.association == association
      }
    end

    it 'should have operators for association' do
      expect(association_operators).not_to be_empty
    end
  end
end