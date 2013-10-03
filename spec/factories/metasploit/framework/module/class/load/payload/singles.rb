FactoryGirl.define do
  factory :metasploit_framework_module_class_load_payload_single,
          class: Metasploit::Framework::Module::Class::Load::Payload::Single,
          parent: :metasploit_framework_module_class_load_payload_base do
    association :module_class,
                factory: :mdm_module_class,
                module_type: Metasploit::Model::Module::Type::PAYLOAD,
                payload_type: 'single'
  end
end