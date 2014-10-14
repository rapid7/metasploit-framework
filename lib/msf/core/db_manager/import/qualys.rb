module Msf::DBManager::Import::Qualys
  autoload :Asset, 'msf/core/db_manager/import/qualys/asset'
  autoload :Scan, 'msf/core/db_manager/import/qualys/scan'

  include Msf::DBManager::Import::Qualys::Asset
  include Msf::DBManager::Import::Qualys::Scan
end