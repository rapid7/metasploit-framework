FactoryBot.define do
  klass = Metasploit::Credential::NTLMHash

  factory :metasploit_credential_ntlm_hash,
          class: klass,
          parent: :metasploit_credential_replayable_hash do
    data {
      klass.data_from_password_data(password_data)
    }
  end
end
