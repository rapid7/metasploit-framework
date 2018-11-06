require_relative 'spec_helper'

require_relative '../lib/dnsruby/resource/GPOS.rb'

# Tests GPOS resource record.  See bottom of file for sample zone file.
class TestGPOS < Minitest::Test

  include Dnsruby

  EXAMPLE_LONGITUDE  = '10.0'
  EXAMPLE_LATITUDE   = '20.0'
  EXAMPLE_ALTITUDE   = '30.0'
  EXAMPLE_HOSTNAME   = 'a.dnsruby.com.'
  EXAMPLE_TTL        = 3 * 60 * 60  # 10,800 seconds, or 3 hours

  EXAMPLE_GPOS_STRING = 'a.dnsruby.com.  10800  IN  GPOS  10.0  20.0  30.0'

  EXAMPLE_GPOS_HASH  = {
      name:       EXAMPLE_HOSTNAME,
      type:       Types::GPOS,
      ttl:        EXAMPLE_TTL,
      longitude:  EXAMPLE_LONGITUDE,
      latitude:   EXAMPLE_LATITUDE,
      altitude:   EXAMPLE_ALTITUDE,
  }

  EXAMPLE_GPOS_DATA = begin
    rdata = RR::GPOS.build_rdata(EXAMPLE_LONGITUDE, EXAMPLE_LATITUDE, EXAMPLE_ALTITUDE)
    [EXAMPLE_HOSTNAME, Types::GPOS, Classes::IN, EXAMPLE_TTL, rdata.length, rdata, 0]
  end

  # Returns a GPOS record returned by a BIND server configured with the zone file
  # shown at the bottom of this file.  I (keithrbennett) was unable to find a GPOS
  # record on the public Internet to use for live testing.
  def gpos_from_response
    # query = Message.new(EXAMPLE_HOSTNAME, 'GPOS')
    # query_binary = "E0\u0000\u0000\u0000\u0001\u0000\u0000\u0000\u0000\u0000\u0000\u0001a\adnsruby\u0003com\u0000\u0000\e\u0000\u0001"
    # response, _error = Resolver.new('127.0.0.1').query_raw(query)

    response_binary = "E0\x84\x80\x00\x01\x00\x01\x00\x01\x00\x01\x01a\adnsruby\x03com\x00\x00\e\x00\x01\xC0\f\x00\e\x00\x01\x00\x00*0\x00\x0F\x0410.0\x0420.0\x0430.0\xC0\x0E\x00\x02\x00\x01\x00\x00*0\x00\x06\x03ns1\xC0\x0E\xC0F\x00\x01\x00\x01\x00\x00*0\x00\x04\x7F\x00\x00\x01"
    response = Message.decode(response_binary)

    # response_binary = "\xE7\x01\x85\x90\x00\x01\x00\x01\x00\x01\x00\x01\x01g\adnsruby\x03com" +
    #     "\x00\x00\e\x00\x01\xC0\f\x00\e\x00\x01\x00\t:\x80\x00\x0F\x0420.0\x0430.0\x0410.0" +
    #     "\xC0\x0E\x00\x02\x00\x01\x00\t:\x80\x00\x05\x02ns\xC0\x0E\xC0F\x00\x01\x00\x01\x00" +
    #     "\t:\x80\x00\x04\xC0\xA8\x01\n"; nil
    #
    # response = Message.decode(response_binary)

    response.answer[0]
  end


  def test_answer
    answer = gpos_from_response
    assert answer.is_a?(RR::GPOS), "Expected RR::GPOS but got a #{answer.class}: #{answer}"
    assert_equal(EXAMPLE_LONGITUDE, answer.longitude)
    assert_equal(EXAMPLE_LATITUDE, answer.latitude)
    assert_equal(EXAMPLE_ALTITUDE, answer.altitude)
    assert_equal(EXAMPLE_TTL, answer.ttl)
  end


  # should be: <owner> <ttl> <class> GPOS <longitude> <latitude> <altitude>
  def test_to_s
    actual = gpos_from_response.to_s.split
    expected = %w(a.dnsruby.com.  10800  IN  GPOS  10.0  20.0  30.0)
    assert_equal(expected, actual)
  end

  def test_creation_approaches

    ans_from_data   = RR::GPOS.new_from_data(*EXAMPLE_GPOS_DATA)
    ans_from_string = RR::GPOS.new_from_string(EXAMPLE_GPOS_STRING)
    ans_from_hash   = RR::GPOS.new_from_hash(EXAMPLE_GPOS_HASH)

    fails_to_populate_rdata = []
    fails_to_populate_rdata << 'data'   if ans_from_data.rdata.nil?
    fails_to_populate_rdata << 'string' if ans_from_string.rdata.nil?
    fails_to_populate_rdata << 'hash'   if ans_from_hash.rdata.nil?

    assert_equal([], fails_to_populate_rdata,
        "Populate modes failing to populate rdata: #{fails_to_populate_rdata.join(', ')}")

    assert_equal(ans_from_data.rdata, ans_from_hash.rdata)
    assert_equal(ans_from_data.rdata, ans_from_string.rdata)

    assert_equal(ans_from_data, ans_from_hash)
    assert_equal(ans_from_data, ans_from_string)
  end

  def test_decode_encode
    response_binary = "E0\x84\x80\x00\x01\x00\x01\x00\x01\x00\x01\x01a\adnsruby\x03com\x00\x00\e\x00\x01\xC0\f\x00\e\x00\x01\x00\x00*0\x00\x0F\x0410.0\x0420.0\x0430.0\xC0\x0E\x00\x02\x00\x01\x00\x00*0\x00\x06\x03ns1\xC0\x0E\xC0F\x00\x01\x00\x01\x00\x00*0\x00\x04\x7F\x00\x00\x01"
    message_object = Message.decode(response_binary)
    reconstructed_binary = message_object.encode
    assert_equal response_binary.force_encoding('ASCII-8BIT'), reconstructed_binary
  end
end


# Sample zone file for setting up BIND to serve GPOS records:
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
        IN      GPOS    10.0    20.0    30.0

b.dnsruby.com.  IN      A       2.4.6.9
        IN      GPOS    40      50      60

=end
