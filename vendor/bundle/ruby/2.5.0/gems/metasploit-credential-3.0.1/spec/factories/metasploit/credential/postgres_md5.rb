FactoryBot.define do
  klass = Metasploit::Credential::PostgresMD5

  factory :metasploit_credential_postgres_md5,
          class: klass,
            parent: :metasploit_credential_replayable_hash do
          data {
            "md5#{SecureRandom.hex(16)}"
          }
          end
end
