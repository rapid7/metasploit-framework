module Msf::DBManager::Import::Nexpose
  autoload :Raw, 'msf/core/db_manager/import/nexpose/raw'
  autoload :Simple, 'msf/core/db_manager/import/nexpose/simple'

  include Msf::DBManager::Import::Nexpose::Raw
  include Msf::DBManager::Import::Nexpose::Simple
end
