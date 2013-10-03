shared_examples_for 'Metasploit::Framework::Module::Cache#prefetch with payload' do |options={}|
  options.assert_valid_keys(:module_classes, :payload_type)

  # use fetch here to fail early and once instead of for each call to
  # `Metapsloit::Framework::Module::Cache#prefetch real_path`.
  module_classes = options.fetch(:module_classes)

  payload_type = options.fetch(:payload_type)

  context "with #{payload_type}" do
    module_type_directory = Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE[Metasploit::Model::Module::Type::PAYLOAD]
    module_type_pathname = Metasploit::Framework.root.join('modules', module_type_directory)
    payload_type_directory = payload_type.pluralize
    payload_type_path = module_type_pathname.join(payload_type_directory).to_path
    rule = File::Find.new(
        ftype: 'file',
        path: payload_type_path,
        pattern: "*#{Metasploit::Model::Module::Ancestor::EXTENSION}"
    )

    rule.find { |real_path|
      it_should_behave_like 'Metasploit::Framework::Module::Cache#prefetch real_path',
                            real_path,
                            module_classes: module_classes
    }
  end
end
