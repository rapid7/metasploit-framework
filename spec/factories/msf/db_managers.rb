FactoryGirl.define do
  factory :msf_db_manager,
          class: Msf::DBManager,
          traits: [
              :metasploit_model_base
          ] do
    association :framework, factory: :msf_framework
  end
end