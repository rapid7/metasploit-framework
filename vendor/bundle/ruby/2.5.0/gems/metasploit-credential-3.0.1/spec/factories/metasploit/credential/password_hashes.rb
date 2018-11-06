FactoryBot.define do
  factory :metasploit_credential_password_hash,
          # no need to declare metasploit_credential_private as the :parent because :metasploit_credential_password_hash
          # uses its own data sequence to differentiate password hashes from other private data and #type is
          # automatically set by ActiveRecord because Metasploit::Credential::Password is an STI subclass.
          class: Metasploit::Credential::Password do
    transient do
      password_data { generate :metasploit_credential_password_data }
    end

    data {
      BCrypt::Password.create(password_data).hash.to_s
    }
  end
end
