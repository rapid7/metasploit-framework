FactoryBot.define do
  factory :metasploit_credential_replayable_hash,
          class: Metasploit::Credential::ReplayableHash,
          parent: :metasploit_credential_password_hash
end
