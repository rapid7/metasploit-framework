# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/module/platform'
require 'rex/text'
require 'pry'

#
# This class provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
module Msf::Payload::Pingback


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

  def initialize(info = {})
    ret = super(info)
    puts("In pingback costructor")
    self.can_cleanup = false
    self.uuid ||= SecureRandom.uuid()
  end

  attr_accessor :uuid
  attr_accessor :can_cleanup
end
