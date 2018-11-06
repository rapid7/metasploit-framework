FactoryBot.define do
  factory :metasploit_credential_origin_import,
          class: Metasploit::Credential::Origin::Import do
    association :task, factory: :mdm_task

    filename { generate :metasploit_credential_origin_import_filename }
  end

  sequence :metasploit_credential_origin_import_filename do |n|
    "metasploit_credential_origin_import_filename#{n}"
  end
end
