# A segment number in an IPv4 address or the
# {MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range#begin} or
# {MetasploitDataModels::IPAddress::V4::Segment::Nmap::Range#send}.
class MetasploitDataModels::IPAddress::V4::Segment::Single < Metasploit::Model::Base
  extend MetasploitDataModels::Match::Child

  include Comparable

  #
  # CONSTANTS
  #

  # Number of bits in a IPv4 segment
  BITS = 8

  # Limit that {#value} can never reach
  LIMIT = 1 << BITS

  # Maximum segment {#value}
  MAXIMUM = LIMIT - 1

  # Minimum segment {#value}
  MINIMUM = 0

  # Regular expression for a segment (octet) of an IPv4 address in decimal dotted notation.
  #
  # @see http://stackoverflow.com/a/17871737/470451
  REGEXP = /(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])/

  #
  # Attributes
  #

  # @!attribute value
  #   The segment number.
  #
  #   @return [Integer, String]
  attr_reader :value

  #
  # Validations
  #

  validates :value,
            numericality: {
                greater_than_or_equal_to: MINIMUM,
                less_than_or_equal_to: MAXIMUM,
                only_integer: true
            }

  #
  # Class Methods
  #

  # (see BITS)
  #
  # @return [Integer] {BITS}
  def self.bits
    BITS
  end

  #
  # Instance Methods
  #

  # Compare this segment to `other`.
  #
  # @param other [#value] another segent to compare against.
  # @return [1] if this segment is greater than `other`.
  # @return [0] if this segment is equal to `other`.
  # @return [-1] if this segment is less than `other`.
  def <=>(other)
    value <=> other.value
  end

  # Full add (as in [full adder](https://en.wikipedia.org/wiki/Full_adder)) two (this segment and `other`) segments and
  # a carry from the previous {#add_with_carry}.
  #
  # @param other [MetasploitDataModels:IPAddress::V4::Segment::Single] segment to add to this segment.
  # @param carry [Integer] integer to add to this segment and other segment from a previous call to {#add_with_carry}
  #   for lower segments.
  # @return [Array<(MetasploitDataModels::IPAddress::V4::Segment::Single, Integer)>] Array containing a proper segment
  #   (where {#value} is less than {LIMIT}) and a carry integer to pass to next call to {#add_with_carry}.
  # @return (see #half_add)
  def add_with_carry(other, carry=0)
    improper_value = self.value + other.value + carry
    proper_value = improper_value % LIMIT
    carry = improper_value / LIMIT
    segment = self.class.new(value: proper_value)

    [segment, carry]
  end

  # The succeeding segment.  Used in `Range`s when walking the `Range`.
  #
  # @return [MetasploitDataModels::IPAddress::V4::Segment::Single] if {#value} responds to `#succ`.
  # @return [nil] otherwise
  def succ
    if value.respond_to? :succ
      self.class.new(value: value.succ)
    end
  end

  delegate :to_s,
           to: :value

  # Sets {#value} by type casting String to Integer.
  #
  # @param formatted_value [#to_s]
  # @return [Integer] if `formatted_value` contains only an Integer#to_s
  # @return [#to_s] `formatted_value` if it does not contain an Integer#to_s
  def value=(formatted_value)
    @value_before_type_cast = formatted_value

    begin
      # use Integer() instead of String#to_i as String#to_i will ignore trailing letters (i.e. '1two' -> 1) and turn all
      # string without an integer in it to 0.
      @value = Integer(formatted_value.to_s)
    rescue ArgumentError
      @value = formatted_value
    end
  end
end