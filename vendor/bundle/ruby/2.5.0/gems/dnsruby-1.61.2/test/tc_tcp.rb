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
class TestTcp < Minitest::Test
  def test_TCP
    res = Dnsruby::Resolver.new()
    res.use_tcp = true
    ret=res.query("example.com")
    assert(ret.is_a?(Dnsruby::Message))
  end
  def test_TCP_port
    #  Need a test server so we can tell what port this message was actually sent on!
    port = nil
    src_port = 57923
    Dnsruby::PacketSender.clear_caches
    received_port = nil
    server_thread = Thread.new {
      ts = TCPServer.new(0)
      port = ts.addr[1]
        t = ts.accept
      #  Check that the source port was src_port
      received_port = t.peeraddr()[1]
      packet = t.recvfrom(2)[0]

      len = (packet[0]<<8)+packet[1]
      if (RUBY_VERSION >= "1.9")
        len = (packet[0].getbyte(0)<<8)+packet[1].getbyte(0)# Ruby 1.9
      end
      packet = t.recvfrom(len)[0]
      tcpPacket = Dnsruby::Message.decode(packet)
      tcpPacket.header.tc = true
      lenmsg = [tcpPacket.encode.length].pack('n')
      t.send(lenmsg, 0)
      t.write(tcpPacket.encode)
      t.close
      ts.close
    }
    ret = nil
    sleep(1)
    client_thread = Thread.new {
#      res = Dnsruby::SingleResolver.new("127.0.0.1")
      res = Dnsruby::SingleResolver.new("localhost")
       res.port = port
      res.use_tcp = true
      res.src_port=src_port
      ret=res.query("example.com")
    }
    server_thread.join
    client_thread.join
    assert(received_port == src_port)
      assert(ret.is_a?(Dnsruby::Message))
  end

#  def test_no_tcp
#    # Try to get a long response (which is truncated) and check that we have
#    @TODO@ FIX THIS TEST!!!
#    # tc bit set
#    res = Dnsruby::Resolver.new()
#    res.udp_size = 512
#    res.no_tcp = true
#    ret = res.query("overflow.dnsruby.validation-test-servers.nominet.org.uk", Dnsruby::Types.TXT)
#    assert(ret.header.tc, "Message should be truncated with no TCP")
#  end

  class HackMessage < Dnsruby::Message
    def wipe_additional
      @additional = Dnsruby::Section.new(self)
    end

    # Decode the encoded message
    def HackMessage.decode(m)
      o = HackMessage.new()
      begin
        Dnsruby::MessageDecoder.new(m) {|msg|
          o.header = Dnsruby::Header.new(msg)
          o.header.qdcount.times {
            question = msg.get_question
            o.question << question
          }
          o.header.ancount.times {
            rr = msg.get_rr
            o.answer << rr
          }
          o.header.nscount.times {
            rr = msg.get_rr
            o.authority << rr
          }
          o.header.arcount.times { |count|
            start = msg.index
            rr = msg.get_rr
            if (rr.type == Dnsruby::Types::TSIG)
              if (count!=o.header.arcount-1)
                Dnsruby.log.Error("Incoming message has TSIG record before last record")
                raise Dnsruby::DecodeError.new("TSIG record present before last record")
              end
              o.tsigstart = start # needed for TSIG verification
            end
            o.additional << rr
          }
        }
      rescue Dnsruby::DecodeError => e
        #  So we got a decode error
        #  However, we might have been able to fill in many parts of the message
        #  So let's raise the DecodeError, but add the partially completed message
        e.partial_message = o
        raise e
      end
      return o
    end

  end

  def test_bad_truncation
    #  Some servers don't do truncation properly.
    #  Make a UDP server which returns large badly formatted packets (arcount > num_additional), with TC bit set
    #  And make a TCP server which returns large well formatted packets
    #  Then make sure that Dnsruby recieves response correctly.
        Dnsruby::PacketSender.clear_caches
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    port = socket.addr[1]
    Thread.new {
      s = socket.recvfrom(65536)
      received_query = s[0]
      socket.connect(s[1][2], s[1][1])
      ans = HackMessage.decode(received_query)
      ans.wipe_additional
      100.times {|i|
      ans.add_additional(Dnsruby::RR.create("example.com 3600 IN A 1.2.3.#{i}"))
      }
      ans.header.arcount = 110
      ans.header.tc = true
      socket.send(ans.encode,0)
    }

        server_thread = Thread.new {
      ts = TCPServer.new(port)
      t = ts.accept
      packet = t.recvfrom(2)[0]

      len = (packet[0]<<8)+packet[1]
      if (RUBY_VERSION >= "1.9")
        len = (packet[0].getbyte(0)<<8)+packet[1].getbyte(0)# Ruby 1.9
      end
      packet = t.recvfrom(len)[0]
      tcpPacket = HackMessage.decode(packet)
            tcpPacket.wipe_additional
      110.times {|i|
      tcpPacket.add_additional(Dnsruby::RR.create("example.com 3600 IN A 1.2.3.#{i}"))
      }
      lenmsg = [tcpPacket.encode.length].pack('n')
      t.send(lenmsg, 0)
      t.write(tcpPacket.encode)
      t.close
      ts.close
    }



        #  Now send query
    res = Dnsruby::Resolver.new("127.0.0.1")
    res.port = port
    res.udp_size = 4096
    assert(res.udp_size == 4096)
    ret = res.query("example.com")
    assert(ret.header.arcount == 110)
    count = 0
    ret.additional.each {|rr| count += 1}
    assert(count == 110)


  end

  # @TODO@ Check stuff like persistent sockets
end
