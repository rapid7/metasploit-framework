module Msf::DBManager::Import::Nessus
  autoload :NBE, 'msf/core/db_manager/import/nessus/nbe'

  include Msf::DBManager::Import::Nessus::NBE
end