require_relative 'spec_helper'

require_relative '../lib/dnsruby/resource/NXT'
require_relative '../lib/dnsruby/code_mappers'

# Tests NXT resource record.  See bottom of file for sample zone file.
class TestNXT < Minitest::Test

  include Dnsruby

  # Get this by running the following script:
  # require 'dnsruby'
  # include Dnsruby
  # query = Message.new('a.dnsruby.com', 'NXT')
  # resolver = Resolver.new('127.0.0.1')
  # response, error = resolver.query_raw(query)
  # puts response.encode.inspect  # to get a quoted string to be inserted in source code


  EXAMPLE_NXT_RESPONSE_AS_BINARY = \
      "\xC2\xE0\x84\x80\x00\x01\x00\x01\x00\x01" +
      "\x00\x01\x01a\adnsruby\x03com\x00" +
      "\x00\x1E\x00\x01\xC0\f\x00\x1E\x00\x01\x00\x00*0\x00\x13\x01b\adnsruby\x03com\x00" +
      "@\x00\x00\n\xC0\x0E\x00\x02\x00\x01\x00\x00*0\x00\x06\x03ns1\xC0\x0E\xC0J\x00\x01\x00" +
      "\x01\x00\x00*0\x00\x04\x7F\x00\x00\x01"

  def test_type_val_to_string
    assert_equal 'SOA', RR::NXT::NxtTypes.code_to_name(6)
    assert_equal 'AXFR', RR::NXT::NxtTypes.code_to_name(252)
    assert_equal 'TYPE9999', RR::NXT::NxtTypes.code_to_name(9999)
  end

  def test_type_name_to_code
    assert_equal 6, RR::NXT::NxtTypes.name_to_code('SOA')
    assert_equal 252, RR::NXT::NxtTypes.name_to_code('AXFR')
    assert_equal 9999, RR::NXT::NxtTypes.name_to_code('TYPE9999')
  end

  def test_type_names_to_codes
    strings = %w(TYPE9999  SOA  AXFR)
    assert_equal [9999, 6, 252], RR::NXT::NxtTypes.names_to_codes(strings)
  end

  def test_type_name_to_codes
    assert_equal [9999, 6, 252], RR::NXT::NxtTypes.names_string_to_codes("TYPE9999  SOA  AXFR")
  end

  def test_codes_to_names
    assert_equal %w(TYPE9999  SOA  AXFR), RR::NXT::NxtTypes.codes_to_names([9999, 6, 252])
  end

  def test_codes_to_string
    assert_equal 'SOA AXFR TYPE9999', RR::NXT::NxtTypes.codes_to_string([6, 252, 9999])
  end

  def test_codes_to_name_sorts_by_code
    assert_equal 'SOA AXFR TYPE9999', RR::NXT::NxtTypes.codes_to_string([9999, 6, 252])
  end

  def test_binary_string_to_codes
    test_type_codes_as_code_array = [1, 6, 28, 100]
    test_type_codes_as_name_array = %w(A  SOA  AAAA  UINFO)
    test_type_codes_as_number = 1267650600228229401496971640898  # (2 ** 1) + (2 ** 6) + (2 ** 28) + (2 ** 100)
    test_type_codes_as_binary_string = "\x10\x0\x0\x0\x0\x0\x0\x0\x0\x10\x0\x0\x42"
    assert_equal(test_type_codes_as_code_array, RR::NXT::NxtTypes.binary_string_to_codes(test_type_codes_as_binary_string))
    assert_equal(test_type_codes_as_name_array, RR::NXT::NxtTypes.binary_string_to_names(test_type_codes_as_binary_string))
    assert_equal(test_type_codes_as_binary_string, RR::NXT::NxtTypes.codes_to_binary_string(test_type_codes_as_code_array))
  end

  def test_that_codes_are_in_range_1_to_127
    TestUtils.assert_not_raised(ArgumentError) { RR::NXT::NxtTypes.codes_to_binary_string([1]) }
    TestUtils.assert_not_raised(ArgumentError) { RR::NXT::NxtTypes.codes_to_binary_string([127]) }
    assert_raises(ArgumentError) { RR::NXT::NxtTypes.codes_to_binary_string([0]) }
    assert_raises(ArgumentError) { RR::NXT::NxtTypes.codes_to_binary_string([128]) }
  end

  def test_that_zero_bit_set_raises_error
    assert_raises(ArgumentError) { RR::NXT::NxtTypes.codes_to_binary_string([]) }
  end

  def test_A_AAAA_NXT
    assert_equal([1, 28, 30], RR::NXT::NxtTypes.names_string_to_codes('A AAAA NXT'))
    assert_equal("P\x00\x00\x02", RR::NXT::NxtTypes.codes_to_binary_string([1, 28, 30]))
  end

  def test_type_bitmap_ctor_is_private
    assert_raises(NoMethodError) { RR::NXT::TypeBitmap.new('') }
  end

  def test_type_bitmap_to_s
    type_bitmap = RR::NXT::TypeBitmap.from_type_codes([1, 16, 30])
    assert_equal('A TXT NXT', type_bitmap.to_s)
  end

  def test_parse_response_correctly
    response = Message.decode(EXAMPLE_NXT_RESPONSE_AS_BINARY)
    answer = response.answer
    nxt_record = answer[0]

    # Note: Although the NXT class is defined as Dnsruby::RR::NXT and not
    # Dnsruby::RR::IN::NXT, the IN module (in IN.rb) creates new classes
    # in the IN module for all class-insensitive resource record classes.
    # When the binary record is parsed, it is a Dnsruby::RR::IN::NXT
    # that is created.
    assert_equal(Dnsruby::RR::IN::NXT, nxt_record.class)
    actual_tokens = nxt_record.to_s.split
    expected_tokens = 'a.dnsruby.com. 10800	IN	NXT	b.dnsruby.com A AAAA NXT'.split
    assert_equal(actual_tokens, expected_tokens)
  end

  def assert_rr_content(rr)
    assert_equal(rr.type, 'NXT') # TODO: Should this be a string or a number?
    assert_equal(rr.name, Name.create('b.dnsruby.com.'))
    assert_equal(rr.ttl, 10800)
    assert_equal(rr.klass, 'IN')
    assert_equal(rr.next_domain, Name.create('a.dnsruby.com.'))
  end

  def test_new_from_string
    rr = RR::NXT.new_from_string('b.dnsruby.com.		10800	IN	NXT	a.dnsruby.com. SOA NXT')
    assert_rr_content(rr)
  end

  def test_new_from_hash
    assert_rr_content(sample_nxt_rr)
  end

  def test_new_from_data
    rdata = RR::NXT.build_rdata('a.dnsruby.com.', [Types::SOA, Types::NXT])

    rr = RR::NXT.new_from_data('b.dnsruby.com.', Types::NXT, Classes::IN, 10800,
        rdata.size, rdata, 0)
    assert_rr_content(rr)
  end

  def test_owner_alias
    rr = sample_nxt_rr
    assert_equal('b.dnsruby.com', rr.owner.to_s)
    assert_equal('b.dnsruby.com', rr.name.to_s)
    new_name = Name.create('z.com')
    rr.owner = new_name
    assert_equal(new_name, rr.owner)
    assert_equal(new_name, rr.name)
  end


  def test_encode_decode_message
    nxt_rr = sample_nxt_rr
    message = Message.new
    message.add_answer(nxt_rr)
    binary_message = message.encode
    reconstructed_message = Message.decode(binary_message)
    reconstructed_nxt_rr = reconstructed_message.answer[0]
    assert_equal(nxt_rr, reconstructed_nxt_rr)
  end

  def sample_nxt_rr
    RR::NXT.new_from_hash(
        name: 'b.dnsruby.com.',
        ttl: 10800,
        klass: Classes::IN,
        next_domain: 'a.dnsruby.com.',
        types: [Types::SOA, Types::NXT])
  end
end



# Sample zone file for setting up BIND to serve a NXT record:
=begin
$TTL    3h

@ IN    SOA     dnsruby.com.    foo.dnsruby.com.        (
        1  ; serial
        3H ; refresh after 3 hours
        1H ; retry after 1 hour
        1W ; expire after 1 week
        1H) ; negative caching TTL of 1 hour

dnsruby.com.    IN      NS      ns1

; Addresses for canonical names

ns1.dnsruby.com.        IN      A       127.0.0.1

a.dnsruby.com.  IN      A       2.4.6.8
        IN      NXT     b A AAAA NXT

b.dnsruby.com.  IN      A       2.4.6.9
        IN      GPOS    40      50      60

=end
