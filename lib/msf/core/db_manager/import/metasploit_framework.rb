module Msf::DBManager::Import::MetasploitFramework
  autoload :XML, 'msf/core/db_manager/import/metasploit_framework/xml'

  include Msf::DBManager::Import::MetasploitFramework::XML
end