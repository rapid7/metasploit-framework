require 'digest/sha1'

FactoryBot.define do
  factory :metasploit_credential_nonreplayable_hash,
          class: Metasploit::Credential::NonreplayableHash,
          parent: :metasploit_credential_password_hash do

    data { generate(:sha1_non_replayable_hash) }
  end


  sequence :sha1_non_replayable_hash do |n|
    Digest::SHA1.hexdigest "hansolo#{n}"
  end
end
