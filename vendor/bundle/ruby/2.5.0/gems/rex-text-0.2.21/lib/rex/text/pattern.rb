# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Creates a pattern that can be used for offset calculation purposes.  This
    # routine is capable of generating patterns using a supplied set and a
    # supplied number of identifiable characters (slots).  The supplied sets
    # should not contain any duplicate characters or the logic will fail.
    #
    # @param length [Integer]
    # @param sets [Array<(String,String,String)>] The character sets to choose
    #   from. Should have 3 elements, each of which must be a string containing
    #   no characters contained in the other sets.
    # @return [String] A pattern of +length+ bytes, in which any 4-byte chunk is
    #   unique
    # @see pattern_offset
    def self.pattern_create(length, sets = nil)
      buf = ''
      offsets = []

      # Make sure there's something in sets even if we were given an explicit nil
      sets ||= [ UpperAlpha, LowerAlpha, Numerals ]

      # Return stupid uses
      return "" if length.to_i < 1
      return sets[0][0].chr * length if sets.size == 1 and sets[0].size == 1

      sets.length.times { offsets << 0 }

      until buf.length >= length
          buf << converge_sets(sets, 0, offsets, length)
      end

      buf[0,length]
    end

    # Step through an arbitrary number of sets of bytes to build up a findable pattern.
    # This is mostly useful for experimentially determining offset lengths into memory
    # structures. Note that the supplied sets should never contain duplicate bytes, or
    # else it can become impossible to measure the offset accurately.
    def self.patt2(len, sets = nil)
      buf = ""
      counter = []
      sets ||= [ UpperAlpha, LowerAlpha, Numerals ]
      len ||= len.to_i
      return "" if len.zero?

      sets = sets.map {|a| a.split(//)}
      sets.size.times { counter << 0}
      0.upto(len-1) do |i|
        setnum = i % sets.size

        #puts counter.inspect
      end

      return buf
    end

    #
    # Calculate the offset to a pattern
    #
    # @param pattern [String] The pattern to search. Usually the return value
    #   from {.pattern_create}
    # @param value [String,Integer]
    # @return [Integer] Index of the given +value+ within +pattern+, if it exists
    # @return [nil] if +pattern+ does not contain +value+
    # @see pattern_create
    def self.pattern_offset(pattern, value, start=0)
      if value.kind_of?(String)
        pattern.index(value, start)
      elsif value.kind_of?(Integer)
        pattern.index([ value ].pack('V'), start)
      else
        raise ::ArgumentError, "Invalid class for value: #{value.class}"
      end
    end

  end
end
