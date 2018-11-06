
FactoryBot.define do
  factory :metasploit_credential_private,
          class: Metasploit::Credential::Private do
    data { generate :metasploit_credential_private_data }
    # only subclasses will populate #type column in STI, so need to fake it to test root class
    type { generate :metasploit_credential_private_type }
  end

  sequence :metasploit_credential_private_data do |n|
    "metasploit_credential_private_data#{n}"
  end

  sequence :metasploit_credential_private_type do |n|
    "Metasploit::Credential::Private::Type#{n}"
  end
end
