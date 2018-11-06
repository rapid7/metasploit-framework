# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'

require 'socket'

class TestRrOpt < Minitest::Test

  include Dnsruby

  # This test illustrates that when an OPT record specifying a maximum
  # UDP size is added to a query, the server will respect that setting
  # and limit the response's size to <= that maximum.
  # This works only with send_plain_message, not send_message, query, etc.
  def test_plain_respects_bufsize

    resolver = Resolver.new('a.gtld-servers.net')

    run_test = ->(bufsize) do

      create_test_query = ->(bufsize) do
        message = Message.new('com', Types.ANY, Classes.IN)
        message.add_additional(RR::OPT.new(bufsize))
        message
      end

      query = create_test_query.(bufsize)
      response, _error = resolver.send_plain_message(query)
      # puts "\nBufsize is #{bufsize}, binary message size is #{response.encode.size}"
      assert_equal(true, response.header.tc)
      assert(response.encode.size <= bufsize)
    end

    run_test.(512)
    run_test.(612)
    run_test.(4096)
  end


  def test_rropt
    size=2048;
    ednsflags=0x9e22;

    optrr = RR::OPT.new(size, ednsflags)

    assert(optrr.dnssec_ok,"DO bit set")
    optrr.dnssec_ok=false
    assert_equal(optrr.flags,0x1e22,"Clearing do, leaving the other bits ");
    assert(!optrr.dnssec_ok,"DO bit cleared")
    optrr.dnssec_ok=true
    assert_equal(optrr.flags,0x9e22,"Clearing do, leaving the other bits ");

    assert_equal(optrr.payloadsize,2048,"Size read")
    assert_equal(optrr.payloadsize=(1498),1498,"Size set")

    optrr.set_client_subnet("0.0.0.0/0")
    assert_equal(optrr.edns_client_subnet,"0.0.0.0/0/0","Wildcard Address")
    optrr.set_client_subnet("216.253.14.2/24")
    assert_equal(optrr.edns_client_subnet,"216.253.14.0/24/0","IPv4 subnet")
    optrr.set_client_subnet("216.253.14.2/1")
    assert_equal(optrr.edns_client_subnet,"216.0.0.0/1/0","IPv4 subnet <8 bits")
    optrr.set_client_subnet("2600:3c00:0:91fd:ab77:157e::/64")
    assert_equal(optrr.edns_client_subnet,"2600:3c00:0:91fd::/64/0","IPv6 subnet")
    optrr.set_client_subnet("2600:3c00:0:91fd:ab77:157e::/7")
    assert_equal(optrr.edns_client_subnet,"2600::/7/0","IPv6 subnet <8 bits")
  end

  def test_resolver_opt_application
    return if (/java/ =~ RUBY_PLATFORM) # @TODO@ Check if this is fixed with JRuby yet
    #  Set up a server running on localhost. Get the resolver to send a
    #  query to it with the UDP size set to 4096. Make sure that it is received
    #  correctly.
    Dnsruby::PacketSender.clear_caches
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    port = socket.addr[1]
    q = Queue.new
    Thread.new {
      s = socket.recvfrom(65536)
      received_query = s[0]
      socket.connect(s[1][2], s[1][1])
      q.push(Message.decode(received_query))
      socket.send(received_query,0)
    }

    #  Now send query
    res = Resolver.new("127.0.0.1")
    res.dnssec = true
    res.port = port
    res.udp_size = 4096
    assert(res.udp_size == 4096)
    res.query("example.com")

    #  Now get received query from the server
    p = q.pop
    #  Now check the query was what we expected
    assert(p.header.arcount == 1)
    assert(p.additional()[0].type = Types.OPT)
    assert(p.additional()[0].klass.code == 4096)
  end

  # Sadly Nominet no longer host these servers :-(
  # def test_large_packet
  #   #  Query TXT for overflow.dnsruby.validation-test-servers.nominet.org.uk
  #   #  with a large udp_size
  #   res = SingleResolver.new
  #   res.udp_size = 4096
  #   ret = res.query("overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT)
  #   assert(ret.rcode == RCode.NoError)
  # end

  def test_decode_opt
    #  Create an OPT RR
    size=2048;
    ednsflags=0x9e22;
    optrr = RR::OPT.new(size, ednsflags)

    #  Add it to a message
    m = Message.new
    m.add_additional(optrr)

    #  Encode the message
    data = m.encode

    #  Decode it
    m2 = Message.decode(data)

    #  Make sure there is an OPT RR there
    assert(m2.rcode == RCode.NOERROR  )
  end

  def test_formerr_response
    #  If we get a FORMERR back from the remote resolver, we should retry with no OPT record
    #  So, we need a server which sends back FORMERR for OPT records, and is OK without them.
    #  Then, we need to get a client to send a request to it (by default adorned with EDNS0),
    #  and make sure that the response is returned to the client OK.
    #  We should then check that the server only received one message with EDNS0, and one message
    #  without.
    return if (/java/ =~ RUBY_PLATFORM) # @TODO@ Check if this is fixed with JRuby yet
    #  Set up a server running on localhost. Get the resolver to send a
    #  query to it with the UDP size set to 4096. Make sure that it is received
    #  correctly.
    Dnsruby::PacketSender.clear_caches
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    port = socket.addr[1]
    q = Queue.new
    Thread.new {
      2.times {
        s = socket.recvfrom(65536)
        received_query = s[0]
        m = Message.decode(received_query)
        q.push(m)
        if (m.header.arcount > 0)
          #  send back FORMERR
          m.header.rcode = RCode.FORMERR
          socket.send(m.encode,0,s[1][2], s[1][1])
        else
          socket.send(received_query,0,s[1][2], s[1][1]) # @TODO@ FORMERR if edns
        end
      }

    }
    #  Now send query
    res = Resolver.new("127.0.0.1")
    res.dnssec = true
    res.port = port
    res.udp_size = 4096
    assert(res.udp_size == 4096)
    ret = res.query("example.com")
    assert(ret.header.get_header_rcode == RCode.NOERROR)
    assert(ret.header.arcount == 0)

    #  Now get received query from the server
    p = q.pop
    #  Now check the query was what we expected
    assert(p.header.arcount == 1)
    assert(p.additional()[0].type = Types.OPT)
    assert(p.additional()[0].klass.code == 4096)

    #  Now check the second message
    assert (!(q.empty?))
    p2 = q.pop
    assert (p2)
    assert(p2.header.arcount == 0)
  end
end
