# -*- coding: binary -*-


#
# Standard Library
#

require 'csv'
require 'fileutils'
require 'shellwords'
require 'tmpdir'
require 'uri'
require 'zip'

#
#
# Gems
#
#

#
# PacketFu
#

require 'packetfu'

#
# Rex
#

require 'rex/socket'

# Check Rex::Parser.nokogiri_loaded for status of the Nokogiri parsers
require 'rex/parser/acunetix_nokogiri'
require 'rex/parser/appscan_nokogiri'
require 'rex/parser/burp_session_nokogiri'
require 'rex/parser/ci_nokogiri'
require 'rex/parser/foundstone_nokogiri'
require 'rex/parser/fusionvm_nokogiri'
require 'rex/parser/mbsa_nokogiri'
require 'rex/parser/nexpose_raw_nokogiri'
require 'rex/parser/nexpose_simple_nokogiri'
require 'rex/parser/nmap_nokogiri'
require 'rex/parser/openvas_nokogiri'
require 'rex/parser/wapiti_nokogiri'

# Legacy XML parsers -- these will be converted some day
require 'rex/parser/ip360_aspl_xml'
require 'rex/parser/ip360_xml'
require 'rex/parser/nessus_xml'
require 'rex/parser/netsparker_xml'
require 'rex/parser/nexpose_xml'
require 'rex/parser/nmap_xml'
require 'rex/parser/retina_xml'

#
# Project
#

require 'msf/base/config'
require 'msf/core'
require 'msf/core/database_event'
require 'msf/core/db_import_error'
require 'msf/core/host_state'
require 'msf/core/service_state'

# The db module provides persistent storage and events.
class Msf::DBManager < Metasploit::Model::Base
  include MonitorMixin

  require 'msf/core/db_manager/activation'
  include Msf::DBManager::Activation

  require 'msf/core/db_manager/client'
  include Msf::DBManager::Client

  require 'msf/core/db_manager/connection'
  include Msf::DBManager::Connection

  require 'msf/core/db_manager/cred'
  include Msf::DBManager::Cred

  require 'msf/core/db_manager/event'
  include Msf::DBManager::Event

  require 'msf/core/db_manager/exploit'
  include Msf::DBManager::Exploit

  require 'msf/core/db_manager/exploited_host'
  include Msf::DBManager::ExploitedHost

  # class declared under Msf::DBManager, so need to require after Msf::DBManager is declared.
  require 'msf/core/db_manager/export'

  require 'msf/core/db_manager/host'
  include Msf::DBManager::Host

  require 'msf/core/db_manager/import'
  include Msf::DBManager::Import

  require 'msf/core/db_manager/loot'
  include Msf::DBManager::Loot

  require 'msf/core/db_manager/migration'
  include Msf::DBManager::Migration

  require 'msf/core/db_manager/note'
  include Msf::DBManager::Note

  require 'msf/core/db_manager/ref'
  include Msf::DBManager::Ref

  require 'msf/core/db_manager/report'
  include Msf::DBManager::Report

  require 'msf/core/db_manager/search'
  include Msf::DBManager::Search

  require 'msf/core/db_manager/service'
  include Msf::DBManager::Service

  require 'msf/core/db_manager/session'
  include Msf::DBManager::Session

  require 'msf/core/db_manager/task'
  include Msf::DBManager::Task

  require 'msf/core/db_manager/validators'
  include Msf::DBManager::Validators

  require 'msf/core/db_manager/vuln'
  include Msf::DBManager::Vuln

  require 'msf/core/db_manager/web'
  include Msf::DBManager::Web

  require 'msf/core/db_manager/wmap'
  include Msf::DBManager::WMAP

  require 'msf/core/db_manager/workspace'
  include Msf::DBManager::Workspace

  #
  # Attributes
  #

  # @!attribute [rw] framework
  #   The framework that is accessing a database through this database manager.
  #
  #   @return [Msf::Framework]
  attr_accessor :framework

  #
  #  Validations
  #

  validates :framework,
            presence: true
end
