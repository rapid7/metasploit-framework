require_relative 'spec_helper'

class TestDNS < Minitest::Test

  def setup
    Dnsruby::Config.reset
  end


  # Illustrates that when a message whose class is 'HS' is sent to
  # a DNS server that does not support the HS class, using send_plain_message,
  # the response returns with an rcode of NOTIMP and a Dnsruby::NotImp error.
  def test_hs_class_returns_notimp_code_and_error
    resolver_host = 'a.gtld-servers.net'
    resolver = Resolver.new(resolver_host)
    message = Message.new('test.com', 'A', 'HS')
    response, error = resolver.send_plain_message(message)

    assert_equal(RCode::NOTIMP, response.rcode)
    assert_equal(Dnsruby::NotImp, error.class)
  end

end
