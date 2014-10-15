module Msf::DBManager::Import::MetasploitFramework
  autoload :XML, 'msf/core/db_manager/import/metasploit_framework/xml'
  autoload :Zip, 'msf/core/db_manager/import/metasploit_framework/zip'

  include Msf::DBManager::Import::MetasploitFramework::XML
  include Msf::DBManager::Import::MetasploitFramework::Zip
end