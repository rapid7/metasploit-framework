# -*- coding => binary -*-

require 'rex/text'

#
# This class provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
module Msf::Payload::Pingback

  attr_accessor :pingback_uuid

  # Generate a Pingback UUID and write it to the database
  def generate_pingback_uuid
    self.pingback_uuid ||= SecureRandom.uuid()
    self.pingback_uuid.to_s.gsub!("-", "")
    datastore['PingbackUUID'] = self.pingback_uuid
    vprint_status("PingbackUUID = #{datastore['PingbackUUID']}")
    if framework.db.active
      vprint_status("Writing UUID #{datastore['PingbackUUID']} to database...")
      framework.db.create_payload(name: datastore['PayloadUUIDName'],
                           uuid: datastore['PingbackUUID'],
                           description: 'pingback',
                           platform: platform.platforms.first.realname.downcase)
    else
      print_warning("Unable to save UUID #{datastore['PingbackUUID']} to database -- database support not active")
    end
    self.pingback_uuid
  end
end
