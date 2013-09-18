shared_examples_for 'Metasploit::Framework::Module::Cache#prefetch deriving module classes' do
  it 'should have module_set derive module classes for Metasploit::Model::Module::Path#module_ancestors Metasploit::Model::Module::Ancestor#module_type' do
    module_ancestors_by_module_type.each do |module_type, module_ancestors|
      module_set = module_manager.module_set_by_module_type[module_type]

      module_set.should_receive(:derive_module_instances) do |module_ancestor_loads|
        module_ancestor_loads.should be_a Array
        module_ancestor_loads.all? { |module_ancestor_load|
          module_ancestor_load.is_a? Metasploit::Framework::Module::Ancestor::Load
        }.should be_true

        actual_real_paths = module_ancestor_loads.map(&:module_ancestor).map(&:real_path)
        # module_ancestors are not created, so real_path is not set.
        expected_real_paths = module_ancestors.map(&:derived_real_path)

        expect(actual_real_paths).to match_array(expected_real_paths)
      end
    end

    prefetch
  end
end