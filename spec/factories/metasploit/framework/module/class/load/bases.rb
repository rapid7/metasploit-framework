FactoryGirl.define do
  factory :metasploit_framework_module_class_load_base,
          class: Metasploit::Framework::Module::Class::Load::Base do
    association :cache, factory: :metasploit_framework_module_cache
    association :module_class, factory: :mdm_module_class
  end
end