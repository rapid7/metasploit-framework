RSpec.shared_examples_for 'MetasploitDataModels::Search::Visitor::Relation#visit matching record' do |options={}|
  options.assert_valid_keys(:attribute, :association)

  attribute = options.fetch(:attribute)
  association = options[:association]

  def self.nested_hash_to_array(association)
    case association
      when Hash
        hash = association
        keys = hash.keys

        unless keys.length == 1
          raise ArgumentError, 'Only single key Hashes are allowed to nest associations'
        end

        parent_association = keys.first
        child_association = hash[parent_association]

        [parent_association, *nested_hash_to_array(child_association)]
      when Symbol
        [association]
      when nil
        []
      else
        raise TypeError, "Cannot convert #{association.class} (#{association}) to array"
    end
  end

  associations = nested_hash_to_array(association)
  messages = [*associations, attribute]
  formatted_operator = messages.map(&:to_s).join('.')

  context "with #{formatted_operator}" do
    let(:formatted) do
      "#{formatted_operator}:\"#{value}\""
    end

    let(:value) do
      messages.inject(matching_record) { |instance, message|
        # wrap in array so singel and plural associatins can be handled the same
        Array.wrap(instance.send(message)).first
      }
    end

    it 'should find only matching record' do
      expect(visit).to match_array([matching_record])
    end
  end
end