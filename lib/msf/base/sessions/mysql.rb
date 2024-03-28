# -*- coding: binary -*-

require 'rex/post/mysql'

class Msf::Sessions::MySQL < Msf::Sessions::Sql

  # @param[Rex::IO::Stream] rstream
  # @param [Hash] opts
  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    self.console = ::Rex::Post::MySQL::Ui::Console.new(self)
    super(rstream, opts)
  end

  # @param [Hash] datastore
  # @param [nil] handler
  # @return [String]
  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    @info = "MySQL #{datastore['USERNAME']} @ #{client.peerinfo}"
  end

  # @return [String] The type of the session
  def self.type
    'mysql'
  end

  # @return [Boolean] Can the session clean up after itself
  def self.can_cleanup_files
    false
  end

  # @return [String] The session description
  def desc
    'MySQL'
  end
end
