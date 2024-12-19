# -*- coding: binary -*-
module Rex
module Proto
module NTP::Constants
  VERSIONS = (0..7).to_a
  MODES = (0..7).to_a
  MODE_6_OPERATIONS = (0..31).to_a
  MODE_7_IMPLEMENTATIONS = (0..255).to_a
  MODE_7_REQUEST_CODES = (0..255).to_a

  module Mode
    # see: https://datatracker.ietf.org/doc/html/rfc5905#section-3
    SYMMETRIC_ACTIVE = 1
    SYMMETRIC_PASSIVE = 2
    CLIENT = 3
    SERVER = 4
    BROADCAST_SERVER = 5
    BROADCAST_CLIENT = 6

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end
  end
end
end
end
