RSpec.shared_examples_for 'payload is not cached' do |options|
  options.assert_valid_keys(:ancestor_reference_names, :reference_name)

  reference_name = options.fetch(:reference_name)

  ancestor_reference_names = options.fetch(:ancestor_reference_names)

  module_type = 'payload'

  context reference_name do
    ancestor_reference_names.each do |ancestor_reference_name|
      it "has listed ancestors '#{module_type}/#{ancestor_reference_name}'" do
        @actual_ancestor_reference_name_set.add(ancestor_reference_name)
      end
    end
  
  end
end
