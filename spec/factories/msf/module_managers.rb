FactoryGirl.define do
  factory :msf_module_manager,
          class: Msf::ModuleManager,
          traits: [
              :metasploit_model_base
          ] do
    #
    # Associations
    #

    association :framework, factory: :msf_simple_framework

    #
    # Attributes
    #

    module_types { Metasploit::Model::Module::Type::ALL }
  end
end