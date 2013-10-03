FactoryGirl.define do
  factory :metasploit_framework_module_class_load_payload_base,
          class: Metasploit::Framework::Module::Class::Load::Payload::Base,
          parent: :metasploit_framework_module_class_load_base do
    association :module_class,
                factory: :mdm_module_class,
                module_type: Metasploit::Model::Module::Type::PAYLOAD
  end
end