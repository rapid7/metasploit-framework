# This code is copied from the trick_bag gem (see https://github.com/keithrbennett/trick_bag).
# It is copied a) to avoid adding a new dependency and b) because that gem is in
# version 0 and is unstable.

module Dnsruby

# Provides methods for converting between the various representations
# of a bitmap: number, binary encoded string, array, and sparse array.
#
# Where an array is used to represent bits, the first element (#0) will be the
# low (1) bit and the last bit will be the high bit.
  module BitMapping

    module_function

    # Converts from a binary string to a number, e.g. "\x01\x00" => 256
    def binary_string_to_number(string)
      string = string.clone.force_encoding(Encoding::ASCII_8BIT)
      string.bytes.inject(0) do |number, byte|
        number * 256 + byte.ord
      end
    end


    # Converts a number to a binary encoded string, e.g. 256 => "\x01\x00"
    def number_to_binary_string(number, min_length = 0)
      assert_non_negative(number)
      binary_string = ''.force_encoding(Encoding::ASCII_8BIT)

      while number > 0
        byte_value = number & 0xFF
        binary_string << byte_value
        number >>= 8
      end

      binary_string.reverse.rjust(min_length, "\x00")
    end


    # Converts a number to an array of place values, e.g. 9 => [8, 0, 0, 1]
    def number_to_place_value_array(number)
      assert_non_negative(number)
      array = []
      bit_value = 1
      while number > 0
        array << ((number & 1 == 1) ? bit_value : 0)
        number >>= 1
        bit_value <<= 1
      end
      array.reverse
    end


    # Converts from a value array to a number, e.g. [8, 0, 0, 1] => 9
    def place_value_array_to_number(place_value_array)
      place_value_array.inject(&:+)
    end


    # Converts a number to an array of bit values, e.g. 9 => [1, 0, 0, 1]
    def number_to_bit_array(number, minimum_binary_places = 0)
      assert_non_negative(number)
      array = []
      while number > 0
        array << (number & 1)
        number >>= 1
      end
      array.reverse!
      zero_pad_count = minimum_binary_places - array.size
      zero_pad_count.times { array.unshift(0) }
      array
    end


    # Converts an array of bit values, e.g. [1, 0, 0, 1], to a number, e.g. 9
    def bit_array_to_number(bit_array)
      return nil if bit_array.empty?
      multiplier = 1
      bit_array.reverse.inject(0) do |result, n|
        result += n * multiplier
        multiplier *= 2
        result
      end
    end


    # Converts a number to a sparse array containing bit positions that are set/true/1.
    # Note that these are bit positions, e.g. 76543210, and not bit column values
    # such as 128/64/32/16/8/4/2/1.
    def number_to_set_bit_positions_array(number)
      assert_non_negative(number)
      array = []
      position = 0
      while number > 0
        array << position if number & 1 == 1
        position += 1
        number >>= 1
      end
      array
    end


    # Converts an array of bit position numbers to a numeric value, e.g. [0, 2] => 5
    def set_bit_position_array_to_number(position_array)
      return nil if position_array.empty?
      position_array.inject(0) do |result, n|
        result += 2 ** n
      end
    end


    # Converts a binary string to an array of bit values, e.g. "\x0C" => [1, 1, 0, 0]
    def binary_string_to_bit_array(string, minimum_binary_places = 0)
      number = binary_string_to_number(string)
      number_to_bit_array(number, minimum_binary_places)
    end


    # If number is negative, raises an ArgumentError; else does nothing.
    def assert_non_negative(number)
      unless number.is_a?(Integer) && number >= 0
        raise ArgumentError.new(
                  "Parameter must be a nonnegative Integer " +
                      "but is #{number.inspect} (a #{number.class})")
      end
    end

    # Reverses a binary string.  Note that it is not enough to reverse
    # the string itself because although the bytes would be reversed,
    # the bits within each byte would not.
    def reverse_binary_string_bits(binary_string)
      binary_place_count = binary_string.size * 8
      reversed_bit_array = binary_string_to_bit_array(binary_string, binary_place_count).reverse
      number = bit_array_to_number(reversed_bit_array)
      number_to_binary_string(number)
    end
  end
end
