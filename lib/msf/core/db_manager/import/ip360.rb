require 'rex/parser/ip360_aspl_xml'

module Msf::DBManager::Import::IP360
  autoload :ASPL, 'msf/core/db_manager/import/ip360/aspl'
  autoload :V3, 'msf/core/db_manager/import/ip360/v3'

  include Msf::DBManager::Import::IP360::ASPL
  include Msf::DBManager::Import::IP360::V3
end