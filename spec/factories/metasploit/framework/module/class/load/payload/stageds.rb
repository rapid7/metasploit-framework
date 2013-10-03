FactoryGirl.define do
  factory :metasploit_framework_module_class_load_payload_staged,
          class: Metasploit::Framework::Module::Class::Load::Payload::Staged,
          parent: :metasploit_framework_module_class_load_payload_base do
    association :module_class,
                factory: :mdm_module_class,
                module_type: Metasploit::Model::Module::Type::PAYLOAD,
                payload_type: 'staged'
  end
end