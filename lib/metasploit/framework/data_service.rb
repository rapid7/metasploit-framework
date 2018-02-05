require 'metasploit/framework/data_service/stubs/host_data_service'
require 'metasploit/framework/data_service/stubs/vuln_data_service'
require 'metasploit/framework/data_service/stubs/event_data_service'
require 'metasploit/framework/data_service/stubs/workspace_data_service'
require 'metasploit/framework/data_service/stubs/note_data_service'
require 'metasploit/framework/data_service/stubs/web_data_service'
require 'metasploit/framework/data_service/stubs/service_data_service'
require 'metasploit/framework/data_service/stubs/session_data_service'
require 'metasploit/framework/data_service/stubs/exploit_data_service'
require 'metasploit/framework/data_service/stubs/loot_data_service'

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
  include ExploitDataService
  include LootDataService

  def name
    raise 'DataLService#name is not implemented';
  end

  def active
    raise 'DataLService#active is not implemented';
  end

  #
  # Hold metadata about a data service
  #
  class Metadata
    attr_reader :id
    attr_reader :name
    attr_reader :active

    def initialize (id, name, active)
      self.id = id
      self.name = name
      self.active = active
    end

    #######
    private
    #######

    attr_writer :id
    attr_writer :name
    attr_writer :active

  end
end
end
end
