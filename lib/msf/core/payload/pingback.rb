# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/module/platform'
require 'rex/text'
require 'pry'

#
# This class provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
class Msf::Payload::Pingback


  #
  # Constants
  #

  def self.generate_raw(opts={})

    puid ||= SecureRandom.uuid
    puid

  end

  #
  # Instance methods
  #

  def initialize(opts=nil)
    super
    self.can_cleanup = true
    self.uuid ||= SecureRandom.uuid()
    opts[:pingback_uuid] = self.uuid
    self.cleans_up = false
    binding.pry
  end

  attr_accessor :uuid
  attr_accessor :can_cleanup
end
