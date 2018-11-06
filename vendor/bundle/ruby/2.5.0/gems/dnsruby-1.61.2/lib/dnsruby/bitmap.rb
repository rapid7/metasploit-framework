# This code is copied from the trick_bag gem (see https://github.com/keithrbennett/trick_bag).
# It is copied a) to avoid adding a new dependency and b) because that gem is in
# version 0 and is unstable.

require_relative = ->(*args) do
  this_file_dir = File.expand_path(File.dirname(__FILE__))
  args.each { |arg| require(File.join(this_file_dir, arg)) }
end

require 'forwardable'
require_relative.('bit_mapping')


module Dnsruby

# Instances of this class can be created that will hold on to bitmap data and be used
# to test bits and convert to other formats.
#
# Where an array is used to represent bits, the first element (#0) will be the
# high bit and the last element will be the low (1's column) bit.
class Bitmap

  extend Forwardable

  # This is the internal representation of the bitmap value:
  attr_reader :number

  # Some instance methods can be delegated to this number:
  [:&, :|, :^, :hash].each do |method_name|
    def_delegator :@number, method_name
  end

  # Set a new value to number, validating first that it is nonnegative.
  def number=(new_number)
    self.assert_non_negative(new_number)
    @number = new_number
  end


  # The constructor is made private because:
  #
  # 1) each type of initialization requires its own validation, and it
  #    would be wasteful to do the validation unnecessarily
  # 2) to enforce that the more descriptively
  #    named class methods should be used to create instances.
  private_class_method :new


  # Class methods to create instances from the various representation types
  # handled in the BitMapping module's methods.

  # Creates an instance from a nonnegative number.
  def self.from_number(number)
    new(number)
  end

  # Creates an instance from a binary string (e.g. "\x0C").
  def self.from_binary_string(string)
    new(BitMapping.binary_string_to_number(string))
  end

  # Creates an instance from a value array (e.g. [8, 0, 0, 1])
  def self.from_place_value_array(array)
    new(BitMapping.place_value_array_to_number(array))
  end

  # Creates an instance from a bit array (e.g. [1, 0, 0, 1])
  def self.from_bit_array(array)
    new(BitMapping.bit_array_to_number(array))
  end

  # Creates an instance from an array of positions for the bits that are set (e.g. [0, 3])
  def self.from_set_bit_position_array(array)
    new(BitMapping.set_bit_position_array_to_number(array))
  end

  # Instance methods to convert the data to the various representation types:

  # Returns the instance's value as a binary string (e.g. "\x0C")
  def to_binary_string(min_length = 0)
    BitMapping.number_to_binary_string(number, min_length)
  end

  # Returns the instance's value as an array of bit column values (e.g. [8, 0, 0, 1])
  def to_place_value_array
    BitMapping.number_to_place_value_array(number)
  end

  # Returns the instance's value as an array of bit column place values (e.g. [8, 0, 0, 1])
  def to_bit_array
    BitMapping.number_to_bit_array(number)
  end

  # Returns the instance's value as an array of positions for the bits that are set (e.g. [0, 3])
  def to_set_bit_position_array
    BitMapping.number_to_set_bit_positions_array(number)
  end

  def initialize(number)
    BitMapping.assert_non_negative(number)
    @number = number
  end

  def ==(other)
    other.is_a?(self.class) && other.number == self.number
  end
end
end
