FactoryBot.define do
  factory :metasploit_credential_public,
          class: Metasploit::Credential::Username do
    transient do
      public_factory { [
        :metasploit_credential_username,
        :metasploit_credential_blank_username
      ].sample
      }

      username {
        if public_factory == :metasploit_credential_username
          generate :metasploit_credential_public_username
        else
          ""
        end
      }
    end

    initialize_with { FactoryBot.build(public_factory, username: username) }
  end

  sequence :metasploit_credential_public_username do |n|
    "metasploit_credential_public_username#{n}"
  end

end