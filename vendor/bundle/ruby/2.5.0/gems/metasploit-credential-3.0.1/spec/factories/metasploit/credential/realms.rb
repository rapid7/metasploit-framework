FactoryBot.define do

  factory :metasploit_credential_realm,
          class: Metasploit::Credential::Realm do
    key { generate :metasploit_credential_realm_key }
    value { generate :metasploit_credential_realm_value }

    factory :metasploit_credential_active_directory_domain do
      key { Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN }
      value { generate :metasploit_credential_active_directory_domain_value }
    end

    factory :metasploit_credential_db2_database do
      key { Metasploit::Model::Realm::Key::DB2_DATABASE }
      value { generate :metasploit_credential_db2_database_value }
    end

    factory :metasploit_credential_oracle_system_identifier do
      key { Metasploit::Model::Realm::Key::ORACLE_SYSTEM_IDENTIFIER }
      value { generate :metasploit_credential_oracle_system_identifier_value }
    end

    factory :metasploit_credential_postgresql_database do
      key { Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE }
      value { generate :metasploit_credential_postgresql_database_value }
    end
  end

  sequence :metasploit_credential_active_directory_domain_value do |n|
    "DOMAIN#{n}"
  end

  sequence :metasploit_credential_db2_database_value do |n|
    "db2_database#{n}"
  end

  sequence :metasploit_credential_oracle_system_identifier_value do |n|
    "oracle_system_identifier#{n}"
  end

  sequence :metasploit_credential_postgresql_database_value do |n|
    "postgressql_database#{n}"
  end

  sequence :metasploit_credential_realm_key, Metasploit::Model::Realm::Key::ALL.cycle

  sequence :metasploit_credential_realm_value do |n|
    "metasploit_credential_realm_value#{n}"
  end
end
