# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/module/platform'
require 'rex/text'

#
# This class provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
class Msf::Payload::Pingback


  #
  # Constants
  #

  #
  # Instance methods
  #

  def initialize(opts=nil)
    self.uuid ||= SecureRandom.uuid
    opts[:pingback_uuid] = self.uuid
  end

  attr_accessor :uuid
end
