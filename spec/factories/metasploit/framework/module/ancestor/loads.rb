FactoryGirl.define do
  factory :metasploit_framework_module_ancestor_load,
          class: Metasploit::Framework::Module::Ancestor::Load,
          traits: [
              :metasploit_model_base
          ] do
    association :module_ancestor, factory: :mdm_module_ancestor
  end
end