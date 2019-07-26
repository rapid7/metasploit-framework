# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/module/platform'
require 'rex/text'

#
# This class provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
module Msf::Payload::Pingback

  attr_accessor :pingback_uuid
  attr_accessor :can_cleanup

  # Generate a Pingback UUID and write it to the database
  def generate_pingback_uuid
    self.pingback_uuid ||= SecureRandom.uuid()
    datastore['PingbackUUID'] = self.pingback_uuid
    vprint_status("PingbackUUID = #{datastore['PingbackUUID'].gsub('-', '')}")
    if framework.db.active
      vprint_status("Writing UUID #{datastore['PingbackUUID'].gsub('-', '')} to database...")
      framework.db.create_payload(name: datastore['PayloadUUIDName'],
                           uuid: datastore['PingbackUUID'].gsub('-', ''),
                           description: 'pingback',
                           platform: platform.platforms.first.realname.downcase)
    else
      print_warning("Unable to save UUID #{datastore['PingbackUUID']} to database -- database support not active")
    end
    self.pingback_uuid
  end

  def initialize(info = {})
    super(info)
    self.can_cleanup = false
    self
  end
end
