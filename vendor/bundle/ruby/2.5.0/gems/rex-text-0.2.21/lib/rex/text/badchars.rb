# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Return the index of the first badchar in +data+, otherwise return
    # nil if there wasn't any badchar occurences.
    #
    # @param data [String] The string to check for bad characters
    # @param badchars [String] A list of characters considered to be bad
    # @return [Integer] Index of the first bad character if any exist in +data+
    # @return [nil] If +data+ contains no bad characters
    def self.badchar_index(data, badchars = '')
      badchars.unpack("C*").each { |badchar|
        pos = data.index(badchar.chr)
        return pos if pos
      }
      return nil
    end

    #
    # Removes bad characters from a string.
    #
    # Modifies +data+ in place
    #
    # @param data [#delete]
    # @param badchars [String] A list of characters considered to be bad
    def self.remove_badchars(data, badchars = '')
      return data if badchars.length == 0
      badchars_pat = badchars.unpack("C*").map{|c| "\\x%.2x" % c}.join
      data.gsub!(/[#{badchars_pat}]/n, '')
      data
    end

    #
    # Returns all chars that are not in the supplied set
    #
    # @param keepers [String]
    # @return [String] All characters not contained in +keepers+
    def self.charset_exclude(keepers)
      excluded_bytes = [*(0..255)] - keepers.unpack("C*")
      excluded_bytes.pack("C*")
    end

  end
end
