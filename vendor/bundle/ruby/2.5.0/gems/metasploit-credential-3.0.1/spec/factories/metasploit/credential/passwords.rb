FactoryBot.define do
  factory :metasploit_credential_password,
          # no need to declare metasploit_credential_private as the :parent because :metasploit_credential_password uses
          # its own data sequence to differentiate passwords from other private data and #type is automatically
          # set by ActiveRecord because Metasploit::Credential::Password is an STI subclass.
          class: Metasploit::Credential::Password do
    data { generate :metasploit_credential_password_data }
  end

  sequence :metasploit_credential_password_data do |n|
    "metasploit_credential_password#{n}"
  end
end
