FactoryGirl.define do
  factory :msf_module_manager, class: Msf::ModuleManager do
    ignore do
      # TODO make Msf::Simple::Framework not construct a module_manager, so this can become an association to msf_simple_framework factory.
      framework { nil }
      types { Metasploit::Model::Module::Type::ALL }
    end

    initialize_with { new(framework, types) }
    # TODO move Msf::ModuleManager to Metasploit::Framework::Module::Class::Manager and be a Metasploit::Model::Base subclass
    skip_create
  end
end