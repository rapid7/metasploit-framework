# Common behavior for Class-InterDomain Routing (`<address>/<prefix-length>`) notation under
# {MetasploitDataModels::IPAddress},
module MetasploitDataModels::IPAddress::CIDR
  # so that translations for errors messages can be filed under metasploit_data_models/ip_address/cidr
  extend ActiveModel::Naming
  extend ActiveSupport::Concern

  #
  # CONSTANTS
  #

  # Separator between the {#address} and {#prefix_length}
  SEPARATOR = '/'

  #
  # Attributes
  #

  # @!attribute address
  #   The IP address being masked by {#prefix_length} `1` bits.
  #
  #   @return [Object] an instance of {address_class}
  attr_reader :address

  # @!attribute prefix_length
  #   The significant number of bits in {#address}.
  #
  #   @return [Integer] number of `1` bits in the netmask of {#address}
  attr_reader :prefix_length

  included do
    include ActiveModel::Validations

    #
    #
    # Validations
    #
    #

    #
    # Validation Methods
    #

    validate :address_valid

    #
    # Attribute Validations
    #

    validates :address,
              presence: true
  end

  # Class methods added to the including `Class`.
  module ClassMethods
    include MetasploitDataModels::Match::Child

    #
    # Attributes
    #

    # @!attribute address_class
    #   The Class` whose instance are usd for {MetasploitDataModels::IPAddress::CIDR#address}.
    #
    #   @return [Class]
    attr_reader :address_class

    #
    # Methods
    #

    # @note `address_class` must respond to `#segment_class` and `#segment_count` so {#maximum_prefix_length} can be
    #   calculated.
    #
    # Sets up the address class and allowed {#maximum_prefix_length} for the including `Class`.
    #
    # @param options [Hash{Symbol => Class}]
    # @option options [Class, #segment_class, #segment_count] :address_class The `Class` whose instances will be used
    #   for {#address}.
    def cidr(options={})
      options.assert_valid_keys(:address_class)

      @address_class = options.fetch(:address_class)

      #
      # Validations
      #

      validates :prefix_length,
                numericality: {
                    only_integer: true,
                    greater_than_or_equal_to: 0,
                    less_than_or_equal_to: maximum_prefix_length
                }
    end

    # Regular expression that matches a string that contains only a CIDR IP address.
    #
    # @return [Regexp]
    def match_regexp
      @match_regexp ||= /\A#{regexp}\z/
    end

    # The maximum number of bits in a prefix for the {#address_class}.
    #
    # @return [Integer] the number of bits across all segments of {#address_class}.
    def maximum_prefix_length
      @maximum_prefix_length ||= address_class.segment_count * address_class.segment_class.bits
    end

    # Regular expression that matches a portion of string that contains a CIDR IP address.
    #
    # @return [Regexp]
    def regexp
      @regexp ||= /(?<address>#{address_class.regexp})#{Regexp.escape(SEPARATOR)}(?<prefix_length>\d+)/
    end
  end

  #
  # Instance Methods
  #

  # Set {#address}.
  #
  # @param formatted_address [#to_s]
  def address=(formatted_address)
    @address = self.class.address_class.new(value: formatted_address)
  end

  # Set {#prefix_length}.
  #
  # @param formatted_prefix_length [#to_s]
  def prefix_length=(formatted_prefix_length)
    @prefix_length_before_type_cast = formatted_prefix_length

    begin
      # use Integer() instead of String#to_i as String#to_i will ignore trailing letters (i.e. '1two' -> 1) and turn all
      # string without an integer in it to 0.
      @prefix_length = Integer(formatted_prefix_length.to_s)
    rescue ArgumentError
      @prefix_length = formatted_prefix_length
    end
  end

  # The formatted_prefix_length passed to {#prefix_length=}
  #
  # @return [#to_s]
  def prefix_length_before_type_cast
    @prefix_length_before_type_cast
  end

  # Parses the `formatted_value` into an {#address} and {#prefix_length}.
  #
  # @param formatted_value [#to_s]
  def value=(formatted_value)
    formatted_address, formatted_prefix_length = formatted_value.to_s.split(SEPARATOR, 2)

    self.address = formatted_address
    self.prefix_length = formatted_prefix_length

    [address, prefix_length]
  end

  private

  # Validates that {#address} is valid.
  #
  # @return [void]
  def address_valid
    if address && !address.valid?
      errors.add(:address, :invalid)
    end
  end
end
