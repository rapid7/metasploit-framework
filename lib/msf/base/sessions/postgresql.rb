# -*- coding: binary -*-

require 'rex/post/postgresql'

class Msf::Sessions::PostgreSQL < Msf::Sessions::Sql

  # @param[Rex::IO::Stream] rstream
  # @param [Hash] opts
  # @param opts [Msf::Db::PostgresPR::Connection] :client
  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    @console = ::Rex::Post::PostgreSQL::Ui::Console.new(self)
    super(rstream, opts)
  end

  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    @info = "PostgreSQL #{datastore['USERNAME']} @ #{@peer_info}"
  end

  #
  # @return [String] The type of the session
  #
  def self.type
    'postgresql'
  end

  #
  # @return [Boolean] Can the session clean up after itself
  def self.can_cleanup_files
    false
  end

  #
  # @return [String] The session description
  #
  def desc
    'PostgreSQL'
  end
end
