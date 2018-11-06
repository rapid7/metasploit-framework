FactoryBot.define do
  factory :metasploit_credential_username,
          class: Metasploit::Credential::Username do
    username { generate :metasploit_credential_public_username }
  end

end