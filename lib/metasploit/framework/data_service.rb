require 'metasploit/framework/data_service/stubs/host_data_service'
require 'metasploit/framework/data_service/stubs/vuln_data_service'
require 'metasploit/framework/data_service/stubs/event_data_service'
require 'metasploit/framework/data_service/stubs/workspace_data_service'
require 'metasploit/framework/data_service/stubs/note_data_service'
require 'metasploit/framework/data_service/stubs/web_data_service'
require 'metasploit/framework/data_service/stubs/service_data_service'
require 'metasploit/framework/data_service/stubs/session_data_service'
require 'metasploit/framework/data_service/stubs/session_event_service'
require 'metasploit/framework/data_service/stubs/exploit_data_service'
require 'metasploit/framework/data_service/stubs/loot_data_service'
require 'metasploit/framework/data_service/stubs/msf_data_service'

#
# All data service implementations should include this module to ensure proper implementation
#
module Metasploit
module Framework
module DataService
  include HostDataService
  include EventDataService
  include VulnDataService
  include WorkspaceDataService
  include WebDataService
  include NoteDataService
  include ServiceDataService
  include SessionDataService
  include SessionEventDataService
  include ExploitDataService
  include LootDataService
  include MsfDataService

  def name
    raise 'DataService#name is not implemented';
  end

  def active
    raise 'DataService#active is not implemented';
  end

  def active=(value)
    raise 'DataService#active= is not implemented';
  end

  def is_local?
    raise 'DataService#is_local? is not implemented';
  end

  #
  # Hold metadata about a data service
  #
  class Metadata
    attr_reader :id
    attr_reader :name
    attr_reader :active
    attr_reader :is_local

    def initialize (id, name, active, is_local)
      self.id = id
      self.name = name
      self.active = active
      self.is_local = is_local

    end

    #######
    private
    #######

    attr_writer :id
    attr_writer :name
    attr_writer :active
    attr_writer :is_local

  end
end
end
end
