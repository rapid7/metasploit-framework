FactoryGirl.define do
  factory :metasploit_framework_module_class_load_non_payload,
          class: Metasploit::Framework::Module::Class::Load::NonPayload,
          parent: :metasploit_framework_module_class_load_base do
    ignore do
      module_type { generate :metasploit_model_non_payload_module_type }
    end

    module_class { create(:mdm_module_class, module_type: module_type) }
  end
end