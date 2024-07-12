# -*- coding:binary -*-

require 'rex/post/mssql'

class Msf::Sessions::MSSQL < Msf::Sessions::Sql

  attr_reader :framework

  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    self.platform = opts.fetch(:platform)
    self.arch = opts.fetch(:arch)
    self.console = ::Rex::Post::MSSQL::Ui::Console.new(self, opts)

    super(rstream, opts)
  end

  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    @info = "MSSQL #{datastore['USERNAME']} @ #{@peer_info}"
  end

  # Returns the type of session.
  #
  def self.type
    'mssql'
  end

  def self.can_cleanup_files
    false
  end

  #
  # Returns the session description.
  #
  def desc
    'MSSQL'
  end
end
