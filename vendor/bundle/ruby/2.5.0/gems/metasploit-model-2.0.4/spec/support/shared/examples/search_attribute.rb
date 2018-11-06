RSpec.shared_examples_for 'search_attribute' do |name, options={}|
  options.assert_valid_keys(:type)
  type = options.fetch(:type)

  it_should_behave_like 'search_with',
                        Metasploit::Model::Search::Operator::Attribute,
                        :attribute => name,
                        :name => name,
                        :type => type

  if type.is_a? Hash
    parent_type, _child_type = type.first

    if parent_type == :set
      attribute_set_method_name = "#{name}_set"

      context attribute_set_method_name do
        subject(attribute_set_method_name) do
          base_class.send(attribute_set_method_name)
        end

        it { is_expected.to be_a Set }
        it { is_expected.not_to be_empty }
      end
    end
  end
end