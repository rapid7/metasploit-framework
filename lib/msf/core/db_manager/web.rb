module Msf::DBManager::Web
  require 'msf/core/db_manager/web/form'
  include Msf::DBManager::Web::Form

  require 'msf/core/db_manager/web/page'
  include Msf::DBManager::Web::Page

  require 'msf/core/db_manager/web/site'
  include Msf::DBManager::Web::Site

  require 'msf/core/db_manager/web/vuln'
  include Msf::DBManager::Web::Vuln
end