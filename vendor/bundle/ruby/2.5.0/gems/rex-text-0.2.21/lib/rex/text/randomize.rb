# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Converts a string to random case
    #
    # @example
    #   Rex::Text.to_rand_case("asdf") # => "asDf"
    #
    # @param str [String] The string to randomize
    # @return [String]
    # @see permute_case
    # @see to_mixed_case_array
    def self.to_rand_case(str)
      buf = str.dup
      0.upto(str.length) do |i|
        buf[i,1] = rand(2) == 0 ? str[i,1].upcase : str[i,1].downcase
      end
      return buf
    end

    #
    # Takes a string, and returns an array of all mixed case versions.
    #
    # @example
    #   >> Rex::Text.to_mixed_case_array "abc1"
    #   => ["abc1", "abC1", "aBc1", "aBC1", "Abc1", "AbC1", "ABc1", "ABC1"]
    #
    # @param str [String] The string to randomize
    # @return [Array<String>]
    # @see permute_case
    def self.to_mixed_case_array(str)
      letters = str.each_char.map { |l| [l.downcase, l.upcase] }
      (1 << str.size).times.map do |i| 
        this_str = ""
        ("%0#{str.size}b" % i).each_char.map(&:to_i).each_with_index do |d,i|
          this_str << letters[i][d]
        end
        this_str
      end.uniq
    end

    #
    # Randomize the whitespace in a string
    #
    def self.randomize_space(str)
      set = ["\x09", "\x20", "\x0d", "\x0a"]
      str.gsub(/\s+/) { |s|
        len = rand(50)+2
        buf = ''
        while (buf.length < len)
          buf << set.sample
        end

        buf
      }
    end

    #
    # Shuffles a byte stream
    #
    # @param str [String]
    # @return [String] The shuffled result
    # @see shuffle_a
    def self.shuffle_s(str)
      shuffle_a(str.unpack("C*")).pack("C*")
    end

    #
    # Performs a Fisher-Yates shuffle on an array
    #
    # Modifies +arr+ in place
    #
    # @param arr [Array] The array to be shuffled
    # @return [Array]
    def self.shuffle_a(arr)
      arr.shuffle!
    end

    # Permute the case of a word
    def self.permute_case(word, idx=0)
      res = []

      if( (UpperAlpha+LowerAlpha).index(word[idx,1]))

        word_ucase = word.dup
        word_ucase[idx, 1] = word[idx, 1].upcase

        word_lcase = word.dup
        word_lcase[idx, 1] = word[idx, 1].downcase

        if (idx == word.length)
          return [word]
        else
          res << permute_case(word_ucase, idx+1)
          res << permute_case(word_lcase, idx+1)
        end
      else
        res << permute_case(word, idx+1)
      end

      res.flatten
    end
  end
end
