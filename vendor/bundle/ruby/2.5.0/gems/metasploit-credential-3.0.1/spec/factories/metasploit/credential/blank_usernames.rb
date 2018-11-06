FactoryBot.define do
  factory :metasploit_credential_blank_username,
          class: Metasploit::Credential::BlankUsername do
    initialize_with { Metasploit::Credential::BlankUsername.where(username: "").first_or_create }
  end
end