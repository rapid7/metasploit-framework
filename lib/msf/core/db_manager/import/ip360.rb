require 'rex/parser/ip360_aspl_xml'

module Msf::DBManager::Import::IP360
  autoload 'ASPL', 'msf/core/db_manager/import/ip360/aspl'

  include Msf::DBManager::Import::IP360::ASPL
end