require 'singleton'
require 'metasploit/framework/database'
require 'rails'

class Msf::WebServices::DBManagerProxy
  include Singleton

  attr_reader :db
  attr_reader :modules

  private

  def initialize
    @modules = Msf::ModuleManager.new(self, Msf::MODULE_TYPES)
    @db = Msf::DBManager.new(self)
    @db.init_db(parse_opts)
  end

  def parse_opts
    opts = {}
    opts['DatabaseYAML'] = Metasploit::Framework::Database.configurations_pathname.try(:to_path)
    opts
  end
end