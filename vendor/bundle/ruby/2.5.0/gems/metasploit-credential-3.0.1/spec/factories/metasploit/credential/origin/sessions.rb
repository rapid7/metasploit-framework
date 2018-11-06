FactoryBot.define do
  factory :metasploit_credential_origin_session,
          class: Metasploit::Credential::Origin::Session do
    association :session, factory: :mdm_session

    post_reference_name { generate :metasploit_credential_origin_session_post_reference_name }
  end

  sequence :metasploit_credential_origin_session_post_reference_name do |n|
    "metasploit/credential/origin/session/post/reference/name#{n}"
  end
end
