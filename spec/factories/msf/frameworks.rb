FactoryGirl.define do
  factory :msf_framework,
          class: Msf::Framework,
          traits: [
              :metasploit_model_base,
              :msf_framework_attributes
          ]

  trait :msf_framework_attributes do
    module_types { Metasploit::Model::Module::Type::ALL }
  end
end