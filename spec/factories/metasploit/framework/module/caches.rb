FactoryGirl.define do
  factory :metasploit_framework_module_cache,
          class: Metasploit::Framework::Module::Cache,
          traits: [
              :metasploit_model_base
          ] do
    association :module_manager, factory: :msf_module_manager
  end
end