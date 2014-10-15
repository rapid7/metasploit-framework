module Msf::DBManager::Import::Nexpose
  autoload :Raw, 'msf/core/db_manager/import/nexpose/raw'

  include Msf::DBManager::Import::Nexpose::Raw
end
