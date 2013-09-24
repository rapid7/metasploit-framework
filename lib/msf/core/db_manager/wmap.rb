module Msf::DBManager::WMAP
  require 'msf/core/db_manager/wmap/request'
  include Msf::DBManager::WMAP::Request

  require 'msf/core/db_manager/wmap/target'
  include Msf::DBManager::WMAP::Target
end