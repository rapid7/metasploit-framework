require 'singleton'
require 'msf/core/db_manager'
require 'metasploit/framework/database'
require 'rails'

class DBManagerProxy
  include Singleton

  attr_reader :db

  private

  def initialize
    @db = Msf::DBManager.new(self)
    @db.init_db(parse_opts)
  end

  def parse_opts
    opts = {}
    opts['DatabaseYAML'] = Metasploit::Framework::Database.configurations_pathname.try(:to_path)
    opts
  end
end