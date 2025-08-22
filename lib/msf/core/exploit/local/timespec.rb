# -*- coding: binary -*-

module Msf
  module Exploit::Local::Timespec
    TIMESPEC_REGEX = %r{
    \b(
      (?:[01]?\d|2[0-3]):[0-5]\d(?:\s?(?:AM|PM))? |            # Matches HH:MM (12h/24h)
      midnight | noon | teatime | now |                        # Matches special keywords
      now\s?\+\s?\d+\s?(?:minutes?|hours?|days?|weeks?) |      # Matches relative times
      (?:mon|tue|wed|thu|fri|sat|sun)(?:day)? |                # Matches named days
      (?:next|last)\s(?:mon|tue|wed|thu|fri|sat|sun)(?:day)? | # Matches next/last weekday
      \d{1,2}/\d{1,2}/\d{2,4} |                                # Matches MM/DD/YY(YY)
      \d{1,2}\.\d{1,2}\.\d{2,4} |                              # Matches DD.MM.YY(YY)
      \d{6} | \d{8}                                            # Matches MMDDYY or MMDDYYYY
    )\b
  }xi # 'x' allows extended mode, 'i' makes it case-insensitive

    #
    # Attempts to validate a timespec.
    #
    # @param timespec [String] The timespec to test
    # @return [Boolean] If the timespec is valid or not
    #
    def self.valid_timespec?(timespec)
      !!(timespec =~ TIMESPEC_REGEX) # Ensures true/false return
    end
  end
end