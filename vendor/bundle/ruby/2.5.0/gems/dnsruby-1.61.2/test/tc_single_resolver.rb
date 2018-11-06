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

class TestSingleResolver < Minitest::Test

  include Dnsruby

  Thread::abort_on_exception = true
  #   Dnsruby.log.level=Logger::DEBUG

  def setup
    Dnsruby::Config.reset
  end

  Rrs = [
      {
          :type => Types.A,
          :name => 'a.t.net-dns.org',
          :address => '10.0.1.128'
      },
      {
          :type => Types::MX,
          :name => 'mx.t.net-dns.org',
          :exchange => 'a.t.net-dns.org',
          :preference => 10
      },
      {
          :type => 'CNAME',
          :name => 'cname.t.net-dns.org',
          :domainname => 'a.t.net-dns.org'
      },
      {
          :type => Types.TXT,
          :name => 'txt.t.net-dns.org',
          :strings => ['Net-DNS']
      }
  ]

  def test_simple
    res = SingleResolver.new()
    m = res.query("ns1.google.com.")
  end

  def test_timeout
    #     if ((RUBY_PLATFORM=~/darwin/) == nil)
    #  Run a query which will not respond, and check that the timeout works
    start_time = 0
    begin
      udps = UDPSocket.new
      udps.bind("127.0.0.1", 0)
      port = *udps.addr.values_at(3, 1)

      begin
        Dnsruby::PacketSender.clear_caches
        res = SingleResolver.new("127.0.0.1")
        res.port = port
        res.packet_timeout=1
        start_time = Time.now.to_i
        m = res.query("a.t.net-dns.org")
        fail "Got response when should have got none"
      rescue ResolvTimeout
        stop_time = Time.now.to_i
        assert((stop_time - start_time) <= (res.packet_timeout * 2),
               "UDP timeout too long : #{stop_time - start_time}" +
                   ", should be #{res.packet_timeout}")
      end
      begin
        Dnsruby::PacketSender.clear_caches
        res = SingleResolver.new("127.0.0.1")
        res.port = port
        res.use_tcp = true
        res.packet_timeout=1
        start_time = Time.now.to_i
#      TheLog.level = Logger::DEBUG
        m = res.query("a.t.net-dns.org")
        fail "TCP timeouts"
      rescue ResolvTimeout
        #         print "Got Timeout for TCP\n"
        stop_time = Time.now.to_i
        assert((stop_time - start_time) <= (res.packet_timeout * 2),
               "TCP timeout too long : #{stop_time - start_time}, should be #{res.packet_timeout}")
      rescue Exception => e
        fail(e)
      end
      TheLog.level = Logger::ERROR
    rescue
      udps.close
    end
  end

  def test_queue_timeout
    port = 46129
#    if (!RUBY_PLATFORM=~/darwin/)
    begin
      udps = UDPSocket.new
      udps.bind("127.0.0.1", 0)
      port = *udps.addr.values_at(3, 1)
      res = SingleResolver.new("127.0.0.1")
      res.dnssec = true
      res.port = port
      res.packet_timeout=1
      q = Queue.new
      msg = Message.new("a.t.net-dns.org")
      res.send_async(msg, q, msg)
      id, ret, error = q.pop
      assert(id==msg)
      assert(ret==nil)
      assert(error.class == ResolvTimeout)
    rescue
      udps.close
    end
#    end
  end

  def test_queries
    res = SingleResolver.new

    Rrs.each do |data|
      packet=nil
      2.times do
        begin
          packet = res.query(data[:name], data[:type])
        rescue ResolvTimeout
        end
        break if packet
      end
      assert(packet)
      assert_equal(packet.question[0].qclass, 'IN', 'Class correct')

      assert(packet, "Got an answer for #{data[:name]} IN #{data[:type]}")
      assert_equal(1, packet.header.qdcount, 'Only one question')
      # assert_equal(1, answer.length, "Got single answer (for question #{data[:name]}")

      question = (packet.question)[0]
      answer = (packet.answer)[0]

      assert(question, 'Got question')
      assert_equal(data[:name], question.qname.to_s, 'Question has right name')
      assert_equal(Types.new(data[:type]), question.qtype, 'Question has right type')
      assert_equal('IN', question.qclass.string, 'Question has right class')

      assert(answer)
      assert_equal(answer.klass, 'IN', 'Class correct')


      data.keys.each do |meth|
        if (meth == :type)
          assert_equal(Types.new(data[meth]).to_s, answer.send(meth).to_s, "#{meth} correct (#{data[:name]})")
        else
          assert_equal(data[meth].to_s, answer.send(meth).to_s, "#{meth} correct (#{data[:name]})")
        end
      end
    end # do
  end

  # test_queries

  #  @TODO@ Although the test_thread_stopped test runs in isolation, it won't run as part
  #  of the whole test suite (ts_dnsruby.rb). Commented out until I can figure out how to
  #  get Test::Unit to run this one sequentially...
  #   def test_thread_stopped
  #     res=SingleResolver.new
  #     # Send a query, and check select_thread running.
  #     m = res.query("example.com")
  #     assert(Dnsruby::SelectThread.instance.select_thread_alive?)
  #     # Wait a second, and check select_thread stopped.
  #     sleep(2)
  #     assert(!Dnsruby::SelectThread.instance.select_thread_alive?)
  #     # Send another query, and check select_thread running.
  #     m = res.query("example.com")
  #     assert(Dnsruby::SelectThread.instance.select_thread_alive?)
  #   end

  def test_res_config
    res = Dnsruby::SingleResolver.new

    res.server=('a.t.net-dns.org')
    ip = res.server
    assert_equal('10.0.1.128', ip.to_s, 'nameserver() looks up IP.')

    res.server=('cname.t.net-dns.org')
    ip = res.server
    assert_equal('10.0.1.128', ip.to_s, 'nameserver() looks up cname.')
  end

  # def test_truncated_response
    # res = SingleResolver.new
    # #     print "Dnssec = #{res.dnssec}\n"
    # # res.server=('ns0.validation-test-servers.nominet.org.uk')
    # res.server=('ns.nlnetlabs.nl')
    # res.packet_timeout = 15
    # begin
      # m = res.query("overflow.net-dns.org", 'txt')
      # assert(m.header.ancount == 62, "62 answer records expected, got #{m.header.ancount}")
      # assert(!m.header.tc, "Message was truncated!")
    # rescue ResolvTimeout => e
    # rescue ServFail => e # not sure why, but we get this on Travis...
    # end
  # end

  def test_illegal_src_port
    #  Try to set src_port to an illegal value - make sure error raised, and port OK
    res = SingleResolver.new
    tests = [53, 387, 1265, 3210, 48619]
    tests.each do |bad_port|
      begin
        res.src_port = bad_port
        fail("bad port #{bad_port}")
      rescue
      end
    end
  end

  def test_add_src_port
    #  Try setting and adding port ranges, and invalid ports, and 0.
    res = SingleResolver.new
    res.src_port = [56789, 56790, 56793]
    assert(res.src_port == [56789, 56790, 56793])
    res.src_port = 56889..56891
    assert(res.src_port == [56889, 56890, 56891])
    res.add_src_port(60000..60002)
    assert(res.src_port == [56889, 56890, 56891, 60000, 60001, 60002])
    res.add_src_port([60004, 60005])
    assert(res.src_port == [56889, 56890, 56891, 60000, 60001, 60002, 60004, 60005])
    res.add_src_port(60006)
    assert(res.src_port == [56889, 56890, 56891, 60000, 60001, 60002, 60004, 60005, 60006])
    #  Now test invalid src_ports
    tests = [0, 53, [60007, 53], [60008, 0], 55..100]
    tests.each do |x|
      begin
        res.add_src_port(x)
        fail()
      rescue
      end
    end
    assert(res.src_port == [56889, 56890, 56891, 60000, 60001, 60002, 60004, 60005, 60006])
  end

  # TODO THIS TEST DOES NOT WORK ON TRAVIS
  # It works fine outside of Travis, so feel free to uncomment it and run it locally
  # Just don't check it in, as Travis will bork - not sure why, something to do with setting up localhost servers
  # def test_options_preserved_on_tcp_resend
  #   #  Send a very small EDNS message to trigger tcp resend.
  #   #  Can we do that without using send_raw and avoiding the case we want to test?
  #   #  Sure - just knock up a little server here, which simply returns the response with the
  #   #  TC bit set, and records both packets sent to it
  #   #  Need to listen once on UDP and once on TCP
  #   udpPacket = nil
  #   tcpPacket = nil
  #   port = 59821
  #   thread = Thread.new {
  #     u = UDPSocket.new()
  #     u.bind("localhost", port)
  #
  #     s = u.recvfrom(15000)
  #     received_query = s[0]
  #     udpPacket = Message.decode(received_query)
  #     u.connect(s[1][2], s[1][1])
  #     udpPacket.header.tc = true
  #     u.send(udpPacket.encode(), 0)
  #     u.close
  #
  #     ts = TCPServer.new(port)
  #     t = ts.accept
  #     packet = t.recvfrom(2)[0]
  #
  #     len = (packet[0]<<8)+packet[1]
  #     if (RUBY_VERSION >= "1.9")
  #       len = (packet[0].getbyte(0)<<8)+packet[1].getbyte(0) # Ruby 1.9
  #     end
  #     packet = t.recvfrom(len)[0]
  #     tcpPacket = Message.decode(packet)
  #     tcpPacket.header.tc = true
  #     lenmsg = [tcpPacket.encode.length].pack('n')
  #     t.send(lenmsg, 0)
  #     t.write(tcpPacket.encode)
  #     t.close
  #     ts.close
  #   }
  #   ret = nil
  #   done = true;
  #   thread2 = Thread.new {
  #     r = SingleResolver.new("localhost")
  #     r.port = port
  #     begin
  #     ret = r.query("example.com")
  #     rescue OtherResolvError => e
  #       done = false
  #     end
  #   }
  #   thread.join
  #   thread2.join
  #   if (done)
  #     assert(tcpPacket && udpPacket)
  #     assert(tcpPacket.header == udpPacket.header)
  #     assert(tcpPacket.additional.rrsets('OPT', true)[0].rrs()[0].ttl == udpPacket.additional.rrsets('OPT', true)[0].rrs()[0].ttl, "UDP : #{udpPacket.additional.rrsets('OPT', true)[0].rrs()[0]}, TCP #{tcpPacket.additional.rrsets('OPT', true)[0].rrs()[0]}")
  #   end
  # end
end
