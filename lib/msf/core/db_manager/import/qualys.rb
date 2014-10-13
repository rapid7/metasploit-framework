module Msf::DBManager::Import::Qualys
  autoload :Asset, 'msf/core/db_manager/import/qualys/asset'

  include Msf::DBManager::Import::Qualys::Asset
end