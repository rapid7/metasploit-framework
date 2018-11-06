FactoryBot.define do
  factory :metasploit_credential_origin_manual,
          class: Metasploit::Credential::Origin::Manual do
    association :user, factory: :mdm_user
  end
end
