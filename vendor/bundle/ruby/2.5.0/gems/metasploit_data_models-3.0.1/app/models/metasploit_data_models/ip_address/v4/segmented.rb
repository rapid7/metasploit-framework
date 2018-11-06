# @note {segment} must be called in subclasses to set the {segment_class_name}.
#
# An IPv4 address that is composed of {SEGMENT_COUNT 4} {#segments} separated by {SEPARATOR `'.'`}.
#
# @example Using single segments to make a single IPv4 address class
#   class MetasploitDataModels::IPAddress::V4::Single < MetasploitDataModels::IPAddress::V4::Segmented
#      #
#      # Segments
#      #
#
#      segment class_name: 'MetasploitDataModels::IPAddress::V4::Segment::Single'
#   end
#
class MetasploitDataModels::IPAddress::V4::Segmented < Metasploit::Model::Base
  extend MetasploitDataModels::Match::Child

  include Comparable

  #
  # CONSTANTS
  #

  # The number of {#segments}
  SEGMENT_COUNT = 4
  # Separator between segments
  SEPARATOR = '.'

  #
  # Attributes
  #

  # @!attribute value
  #   Segments of IP address from high to low.
  #
  #   @return [Array<MetasploitDataModels::IPAddress:V4::Segment::Nmap>]
  attr_reader :value

  #
  #
  # Validations
  #
  #

  #
  # Validation Methods
  #

  validate :segments_valid

  #
  # Attribute Validations
  #

  validates :segments,
            length: {
              is: SEGMENT_COUNT
            }

  #
  # Class methods
  #

  # @note Call {segment} with the {segment_class_name} before calling this method, as it uses {segment_class} to look
  #   up the `REGEXP` of the {segment_class}.
  #
  # Regular expression that matches the part of a string that represents a IPv4 segmented IP address format.
  #
  # @return [Regexp]
  def self.regexp
    unless instance_variable_defined? :@regexp
      separated_segment_count = SEGMENT_COUNT - 1

      @regexp = %r{
        (#{segment_class::REGEXP}#{Regexp.escape(SEPARATOR)}){#{separated_segment_count},#{separated_segment_count}}
        #{segment_class::REGEXP}
      }x
    end

    @regexp
  end

  # Sets up the {segment_class_name} for the subclass.
  #
  # @example Using {segment} to set {segment_class_name}
  #   segment class_name: 'MetasploitDataModels::IPAddress::V4::Segment::Single'
  #
  # @param options [Hash{Symbol => String}]
  # @option options [String] :class_name a `Class#name` to use for {segment_class_name}.
  # @return [void]
  def self.segment(options={})
    options.assert_valid_keys(:class_name)

    @segment_class_name = options.fetch(:class_name)
  end

  # @note Call {segment} to set the {segment_class_name} before calling {segment_class}, which will attempt to
  #   String#constantize` {segment_class_name}.
  #
  # The `Class` used to parse each segment of the IPv4 address.
  #
  # @return [Class]
  def self.segment_class
    @segment_class = segment_class_name.constantize
  end

  # @note Call {segment} to set {segment_class_name}
  #
  # The name of {segment_class}
  #
  # @return [String] a `Class#name` for {segment_class}.
  def self.segment_class_name
    @segment_class_name
  end

  # (see SEGMENT_COUNT)
  #
  # @return [Integer]
  def self.segment_count
    SEGMENT_COUNT
  end

  #
  # Instance methods
  #

  # Compare this segment IPv4 address to `other`.
  #
  # @return [1] if {#segments} are greater than {#segments} of `other`.
  # @return [0] if {#segments} are equal to {#segments} of `other`.
  # @return [-1] if {#segments} are less than {#segments} of `other`.
  # @return [nil] if `other` isn't the same `Class`
  def <=>(other)
    if other.is_a? self.class
      segments <=> other.segments
    else
      # The interface for <=> requires nil be returned if other is incomparable
      nil
    end
  end

  # Array of segments.
  #
  # @return [Array] if {#value} is an `Array`.
  # @return [[]] if {#value} is not an `Array`.
  def segments
    if value.is_a? Array
      value
    else
      []
    end
  end

  # Set {#segments}.
  #
  # @param segments [Array] `Array` of {segment_class} instances
  # @return [Array] `Array` of {segment_class} instances
  def segments=(segments)
    @value = segments
  end

  # Segments joined with {SEPARATOR}.
  #
  # @return [String]
  def to_s
    segments.map(&:to_s).join(SEPARATOR)
  end

  # @note Set {#segments} if value is not formatted, but already broken into an `Array` of {segment_class} instances.
  #
  # Sets {#value} by parsing its segments.
  #
  # @param formatted_value [#to_s]
  def value=(formatted_value)
    string = formatted_value.to_s
    match = self.class.match_regexp.match(string)

    if match
      segments = string.split(SEPARATOR)

      @value = segments.map { |segment|
        self.class.segment_class.new(value: segment)
      }
    else
      @value = formatted_value
    end
  end

  private

  # Validates that all segments in {#segments} are valid.
  #
  # @return [void]
  def segments_valid
    segments.each_with_index do |segment, index|
      unless segment.valid?
        errors.add(:segments, :segment_invalid, index: index, segment: segment)
      end
    end
  end
end