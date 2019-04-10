# -*- coding: binary -*-
require 'msf/base'

module Msf
module Sessions

###
#
# This class provides basic interaction with a command shell on the remote
# endpoint.  This session is initialized with a stream that will be used
# as the pipe for reading and writing the command shell.
#
###
class Pingback

  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  #
  # Returns the type of session.
  #
  def self.type
    "pingback"
  end

  def initialize(conn, opts = {})
    self.platform ||= ""
    self.arch     ||= ""
    datastore = opts[:datastore]
    super
  end

  #
  # Returns the session description.
  #
  def desc
    "Pingback"
  end

  #
  # Calls the class method
  #
  def type
    self.class.type
  end

  attr_accessor :arch
  attr_accessor :platform

end

end
end
