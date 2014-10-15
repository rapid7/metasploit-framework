module Msf::DBManager::Import::Nessus
  autoload :NBE, 'msf/core/db_manager/import/nessus/nbe'
  autoload :XML, 'msf/core/db_manager/import/nessus/xml'

  include Msf::DBManager::Import::Nessus::NBE
  include Msf::DBManager::Import::Nessus::XML
end