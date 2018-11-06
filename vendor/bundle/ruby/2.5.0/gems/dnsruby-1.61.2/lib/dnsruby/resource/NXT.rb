require_relative = ->(*args) do
  this_file_dir = File.expand_path(File.dirname(__FILE__))
  args.each { |arg| require(File.join(this_file_dir, arg)) }
end

require_relative.('../bitmap', '../bit_mapping', 'RR')

module Dnsruby
class RR

# Class for NXT resource records.
#
# NXT-specific data types, present in RDATA, are:
#   next_domain: the next domain name, as a Name instance
#   types: array of record types as numbers
#
# RFC 2535 (https://www.ietf.org/rfc/rfc2535.txt)
#
# The RFC mentions that a low bit of zero in the type RDATA
# indicates that the highest type code does not exceed 127,
# and that a low bit of 1 indicates that some mechanism
# other than a bitmap is being used.  This class does not
# support such non-bitmap mechanisms, and assumes there
# will always be a bitmap.
class NXT < RR

  ClassHash[[TypeValue = Types::NXT, Classes::IN]] = self #:nodoc: all

  attr_accessor :next_domain, :types

  REQUIRED_KEYS = [:next_domain, :types]

  def from_hash(params_hash)
    unless REQUIRED_KEYS.all? { |key| params_hash[key] }
      raise ArgumentError.new("NXT hash must contain all of: #{REQUIRED_KEYS.join(', ')}.")
    end
    @next_domain = Name.create(params_hash[:next_domain]) unless @next_domain.is_a?(Name)
    @types       = params_hash[:types]
  end

  def from_data(data)
    next_domain, types = data
    from_hash(next_domain: next_domain, types: types)
  end

  def from_string(string)
    next_domain, *type_names = string.split  # type names are all but first
    types = NxtTypes::names_to_codes(type_names)
    from_hash(next_domain: next_domain, types: types)
  end

  # As with all resource record subclasses of RR, this class cannot be
  # directly instantiated, but instead must be instantiated via use of
  # one of the RR class methods.  These NXT class methods are wrappers
  # around those RR methods, so that there is an interface on the NXT
  # class for creating NXT instances.

  # Create an instance from a hash of parameters, e.g.:
  #
  # rr = RR::NXT.new_from_hash(
  #     name: 'b.dnsruby.com.',
  #     ttl: 10800,
  #     klass: Classes::IN,
  #     next_domain: 'a.dnsruby.com.',
  #     types: [Types::SOA, Types::NXT])
  #
  # Since the type is assumed to be NXT, it will be assigned
  # automatically, and any other value will be overwritten.
  # Therefore, having it present in the hash is not necessary.
  def self.new_from_hash(params_hash)
    params_hash[:type] = Types::NXT
    RR.new_from_hash(params_hash)
  end

  # Create an instance from a string containing parameters, e.g.:
  # b.dnsruby.com.  10800  IN  NXT  A.dnsruby.com.  SOA  NXT
  def self.new_from_string(params_string)
    RR.new_from_string(params_string)
  end

  # Create an instance from an ordered parameter list, e.g.:
  # rdata = RR::NXT.build_rdata('a.dnsruby.com.', [Types::SOA, Types::NXT])
  #
  # rr = RR::NXT.new_from_data('b.dnsruby.com.', Types::NXT,
  #     Classes::IN, 10800, rdata.size, rdata, 0)
  def self.new_from_data(*params_data)
    RR.new_from_data(*params_data)
  end

  # Builds rdata from the provided information.
  # @param next_domain either a string or a Name
  # @param types an array of types (where each type is the numeric type code)
  #        or a TypeBitmap
  def self.build_rdata(next_domain, types)
    next_domain = Name.create(next_domain) if next_domain.is_a?(String)
    types = TypeBitmap.from_type_codes(types) if types.is_a?(Array)

    binary_string = ''.force_encoding('ASCII-8BIT')
    binary_string << next_domain.canonical
    binary_string << BitMapping.reverse_binary_string_bits(types.to_binary_string)
    binary_string
  end

  # From the RFC:
  # NXT has the following format:
  # foo.nil.    NXT big.foo.nil NS KEY SOA NXT
  # <owner> NXT <next_domain> <record types>
  #
  # We handle the rdata, the RR superclass does the rest.
  def rdata_to_string
    "#{next_domain} #{NxtTypes.codes_to_names(types).join(' ')}"
  end

  def encode_rdata(message_encoder, _canonical)
    message_encoder.put_bytes(build_rdata)
  end

  def build_rdata
    self.class.build_rdata(next_domain, types)
  end

  def self.decode_rdata(message_decoder)

    start_index = message_decoder.index

    rdata_len = -> do
      rdata_length_str = message_decoder.data[start_index - 2, 2]
      rdata_length_str.unpack('n').first
    end

    next_domain_and_bitmap = -> do
      next_domain = message_decoder.get_name
      bitmap_start_index = message_decoder.index

      # If we're being called from new_from_data, the MessageDecoder
      # contains only the rdata, not the entire message, and there will
      # be no encoded length for us to read.
      called_from_new_from_data = (start_index == 0)
      bitmap_length = called_from_new_from_data \
          ? message_decoder.data.size \
          : rdata_len.() - (bitmap_start_index - start_index)

      bitmap = message_decoder.get_bytes(bitmap_length)
      bitmap = BitMapping.reverse_binary_string_bits(bitmap)
      [next_domain, bitmap]
    end

    next_domain, type_bitmap = next_domain_and_bitmap.()
    types = TypeBitmap.from_binary_string(type_bitmap).to_type_array
    new(next_domain: next_domain, types: types)
  end

  # 'name' is used in the RR superclass, but 'owner' is the term referred to
  # in the RFC, so we'll make owner an alias for name.
  alias_method(:owner,  :name)
  alias_method(:owner=, :name=)


  # Methods used to manipulate the storage and representation of
  # record types as stored in NXT record bitmaps.
  module NxtTypes

    module_function

    # Maximum bitmap size is 128 bytes; since it's zero offset
    # values are 0..(2 ** 128 - 1).  However, the least
    # significant bit must not be set, so the maximum is 1 less than that.
    MAX_BITMAP_NUMBER_VALUE = (2 ** 128) - 1 - 1

    # Convert a numeric type code to its corresponding name (e.g. "A" => 1).
    # Unknown types are named "TYPE#{number}".
    def code_to_name(number)
      Types.to_string(number) || "TYPE#{number}"
    end

    # Convert a type name to its corresponding numeric type code.
    # Names matching /^TYPE(\d+)$/ are assumed to have a code
    # corresponding to the numeric value of the substring following 'TYPE'.
    def name_to_code(name)
      code = Types.to_code(name)
      if code.nil?
        matches = /^TYPE(\d+)$/.match(name)
        code = matches[1].to_i if matches
      end
      code
    end

    # For a given array of type names, return an array of codes.
    def names_to_codes(names)
      names.map { |s| name_to_code(s) }
    end

    # For the specified string containing names (e.g. 'A NS'),
    # return an array containing the corresponding codes.
    def names_string_to_codes(name_string)
      names_to_codes(name_string.split(' '))
    end

    # For the given array of type codes, return an array of their
    # corresponding names.
    def codes_to_names(codes)
      codes.map { |code| code_to_name(code) }
    end

    # Generate a string containing the names corresponding to the
    # numeric type codes.  Sort it by the numeric type code, ascending.
    def codes_to_string(codes)
      codes.sort.map { |code| code_to_name(code) }.join(' ')
    end

    # From a binary string of type code bits, return an array
    # of type codes.
    def binary_string_to_codes(binary_string)
      bitmap_number = BitMapping.binary_string_to_number(binary_string)
      assert_legal_bitmap_value(bitmap_number)
      BitMapping.number_to_set_bit_positions_array(bitmap_number)
    end

    # From a binary string of type code bits, return an array
    # of type names.
    def binary_string_to_names(binary_string)
      codes = binary_string_to_codes(binary_string)
      codes_to_names(codes)
    end

    # From an array of type codes, return a binary string.
    def codes_to_binary_string(codes)
      codes = codes.sort
      unless legal_code_value?(codes.first) && legal_code_value?(codes.last)
        raise ArgumentError.new("All codes must be between 1 and 127: #{codes.inspect}.")
      end
      bitmap_number = BitMapping.set_bit_position_array_to_number(codes)
      BitMapping.number_to_binary_string(bitmap_number)
    end

    # Assert that the specified number is a legal value with which to
    # instantiate a NXT type bitmap.  Raise on error, do nothing on success.
    def assert_legal_bitmap_value(number)
      max_value = NxtTypes::MAX_BITMAP_NUMBER_VALUE
      if number > max_value
        raise ArgumentError.new("Bitmap maximum value is #{max_value} (0x#{max_value.to_s(16)}).")
      end
      if number & 1 == 1
        raise ArgumentError.new("Bitmap number must not have low bit set.")
      end
    end

    def legal_code_value?(code)
      (1..127).include?(code)
    end
  end


  class TypeBitmap

    attr_accessor :bitmap

    # Create an instance from a string containing type names separated by spaces
    # e.g. "A TXT NXT"
    def self.from_names_string(names_string)
      type_codes = BitMapping.names_string_to_codes(names_string)
      from_type_codes(type_codes)
    end

    # Create an instance from type numeric codes (e.g. 30 for NXT).
    def self.from_type_codes(type_codes)
      new(BitMapping.set_bit_position_array_to_number(type_codes))
    end

    # Create an instance from a binary string, e.g. from a NXT record RDATA:
    def self.from_binary_string(binary_string)
      new(BitMapping.binary_string_to_number(binary_string))
    end

    # The constructor is made private so that the name of the method called
    # to create the instance reveals to the reader the type of the initial data.
    private_class_method :new
    def initialize(bitmap_number)
      NxtTypes.assert_legal_bitmap_value(bitmap_number)
      @bitmap = Bitmap.from_number(bitmap_number)
    end

    # Returns a binary string representing this data, in as few bytes as possible
    # (i.e. no leading zero bytes).
    def to_binary_string
      bitmap.to_binary_string
    end

    # Returns the instance's data as an array of type codes.
    def to_type_array
      bitmap.to_set_bit_position_array
    end

    # Output types in dig format, e.g. "A AAAA NXT"
    def to_s
      type_codes = bitmap.to_set_bit_position_array
      NxtTypes.codes_to_string(type_codes)
    end
  end
end
end
end
