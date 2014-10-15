module Msf::DBManager::Import::MetasploitFramework
  autoload :Credential, 'msf/core/db_manager/import/metasploit_framework/credential'
  autoload :XML, 'msf/core/db_manager/import/metasploit_framework/xml'
  autoload :Zip, 'msf/core/db_manager/import/metasploit_framework/zip'

  include Msf::DBManager::Import::MetasploitFramework::Credential
  include Msf::DBManager::Import::MetasploitFramework::XML
  include Msf::DBManager::Import::MetasploitFramework::Zip

  # Convert the string "NULL" to actual nil
  def nils_for_nulls(str)
    str == "NULL" ? nil : str
  end
end