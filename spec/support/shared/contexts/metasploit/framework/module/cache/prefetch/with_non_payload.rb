shared_examples_for 'Metasploit::Framework::Module::Cache#prefetch with non-payload' do |options={}|
  options.assert_valid_keys(:module_type)

  module_type = options.fetch(:module_type)

  context "with #{module_type}" do
    module_type_directory = Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE[module_type]
    module_type_path = Metasploit::Framework.root.join('modules', module_type_directory).to_path
    rule = File::Find.new(
        ftype: 'file',
        path: module_type_path,
        pattern: "*#{Metasploit::Model::Module::Ancestor::EXTENSION}"
    )

    rule.find { |real_path|
      it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch real_path',
                            real_path,
                            module_classes: :have_exactly
    }
  end
end