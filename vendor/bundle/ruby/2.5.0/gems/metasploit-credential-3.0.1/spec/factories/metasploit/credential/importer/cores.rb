FactoryBot.define do
  long_form_headers  = 'username,private_type,private_data,realm_key,realm_value,host_address,service_port,service_name,service_protocol,status,access_level,last_attempted_at'
  short_form_headers = 'username,private_data'
  login_status       = Metasploit::Model::Login::Status::ALL.select {|x| x != Metasploit::Model::Login::Status::UNTRIED }.sample
  access_level       = ['Admin', 'Foo'].sample
  last_attempted_at  = Time.now - 10

  factory :metasploit_credential_core_importer,
          class: Metasploit::Credential::Importer::Core do
            origin { FactoryBot.build :metasploit_credential_origin_import }
            input  { generate(:well_formed_csv_compliant_header) }
  end


  # Well-formed CSV
  # Has a compliant header as defined by Metasploit::Credential::Importer::Core
  # Contains 2 realms
  sequence :well_formed_csv_compliant_header do |n|
    csv_string =<<-eos
#{long_form_headers}
han_solo-#{n},#{Metasploit::Credential::Password.name},falcon_chief,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels,,,,,#{login_status},#{access_level},#{last_attempted_at}
princessl-#{n},#{Metasploit::Credential::Password.name},bagel_head,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels,,,,,#{login_status},#{access_level},#{last_attempted_at}
lord_vader-#{n},#{Metasploit::Credential::Password.name},evilisfun,#{Metasploit::Model::Realm::Key::ORACLE_SYSTEM_IDENTIFIER},dstar_admins,,,,,#{login_status},#{access_level},#{last_attempted_at}
    eos
    StringIO.new(csv_string)
  end

  # Well-formed CSV
  # Has a compliant header as defined by Metasploit::Credential::Importer::Core
  # Contains 2 logins
  sequence :well_formed_csv_compliant_header_with_service_info do |n|
    csv_string =<<-eos
#{long_form_headers}
han_solo-#{n},#{Metasploit::Credential::Password.name},falcon_chief,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels,10.0.1.1,1234,smb,tcp,#{login_status},#{access_level},#{last_attempted_at}
princessl-#{n},#{Metasploit::Credential::Password.name},bagel_head,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels,10.0.1.2,1234,smb,tcp,#{login_status},#{access_level},#{last_attempted_at}
lord_vader-#{n},#{Metasploit::Credential::Password.name},evilisfun,#{Metasploit::Model::Realm::Key::ORACLE_SYSTEM_IDENTIFIER},dstar_admins,#{login_status},#{access_level},#{last_attempted_at}
    eos
    StringIO.new(csv_string)
  end

  # Well-formed CSV
  # Has a compliant header as defined by Metasploit::Credential::Importer::Core
  # Contains no realm data
  sequence :well_formed_csv_compliant_header_no_realm do |n|
    csv_string =<<-eos
#{long_form_headers}
han_solo-#{n},#{Metasploit::Credential::Password.name},falcon_chief,,,,,,#{login_status},#{access_level},#{last_attempted_at},,,,,#{login_status},#{access_level},#{last_attempted_at}
princessl-#{n},#{Metasploit::Credential::Password.name},bagel_head,,,,,,#{login_status},#{access_level},#{last_attempted_at},,,,,#{login_status},#{access_level},#{last_attempted_at}
lord_vader-#{n},#{Metasploit::Credential::Password.name},evilisfun,,,,,,#{login_status},#{access_level},#{last_attempted_at},,,,,#{login_status},#{access_level},#{last_attempted_at}
    eos
    StringIO.new(csv_string)
  end

  # Well-formed CSV
  # Has a compliant header as defined by Metasploit::Credential::Importer::Core
  # Contains 2 logins
  # Contains core with a blank Public
  sequence :well_formed_csv_compliant_header_missing_public do |n|
    csv_string =<<-eos
#{long_form_headers}
,#{Metasploit::Credential::Password.name},falcon_chief,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels,,,,,#{login_status},#{access_level},#{last_attempted_at}
princessl-#{n},#{Metasploit::Credential::Password.name},bagel_head,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels,,,,,#{login_status},#{access_level},#{last_attempted_at}
lord_vader-#{n},#{Metasploit::Credential::Password.name},evilisfun,#{Metasploit::Model::Realm::Key::ORACLE_SYSTEM_IDENTIFIER},dstar_admins,,,,,#{login_status},#{access_level},#{last_attempted_at}
    eos
    StringIO.new(csv_string)
  end

  # Well-formed CSV
  # Has a compliant header as defined by Metasploit::Credential::Importer::Core
  # Contains 2 logins
  # Contains core with a blank Private
  sequence :well_formed_csv_compliant_header_missing_private do |n|
    csv_string =<<-eos
#{long_form_headers}
han_solo,,,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels
princessl-#{n},#{Metasploit::Credential::Password.name},bagel_head,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels
lord_vader-#{n},#{Metasploit::Credential::Password.name},evilisfun,#{Metasploit::Model::Realm::Key::ORACLE_SYSTEM_IDENTIFIER},dstar_admins
    eos
    StringIO.new(csv_string)
  end


  # Well-formed CSV
  # Conforms to "short" form, in which only username and private_data are specified in the file
  sequence :short_well_formed_csv do |n|
    csv_string =<<-eos
#{short_form_headers}
han_solo-#{n},falC0nBaws
princessl-#{n},bagelHead
    eos
    StringIO.new(csv_string)
  end

  # Well-formed CSV, non-compliant headers
  # Conforms to "short" form, in which only username and private_data are specified in the file
  sequence :short_well_formed_csv_non_compliant_header do |n|
    csv_string =<<-eos
bad,wrong
han_solo-#{n},falC0nBaws
princessl-#{n},bagelHead
    eos
    StringIO.new(csv_string)
  end

  sequence :well_formed_csv_non_compliant_header do |n|
    csv_string =<<-eos
notgood,noncompliant,badheader,morebadheader
han_solo-#{n},#{Metasploit::Credential::Password.name},falcon_chief, #{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels
princessl-#{n},#{Metasploit::Credential::Password.name},bagel_head,#{Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN},Rebels
    eos
    StringIO.new(csv_string)
  end

  # Odd number of quotes will throw CSV::MalformedCSVError
  sequence :malformed_csv do |n|
    csv_string =<<-eos
foo,{"""}
    eos
    StringIO.new(csv_string)
  end

  # We have a header row but nothing else
  sequence :empty_core_csv do |n|
    csv_string =<<-eos
#{long_form_headers}
    eos
    StringIO.new(csv_string)
  end
end
