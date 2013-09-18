FactoryGirl.define do
  factory :msf_module_manager,
          class: Msf::ModuleManager,
          traits: [
              :metasploit_model_base
          ] do
    # TODO make Msf::Simple::Framework not construct a module_manager, so this can become an association to msf_simple_framework factory.
    framework { nil }
    module_types { Metasploit::Model::Module::Type::ALL }
  end
end