#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

class String
  def bin
    self.scan(/../).map {|x| x.to_i(16).chr}.join
  end
end

class TcpEcnTest < Test::Unit::TestCase
  include PacketFu

  def test_ecn_set
    t = TcpEcn.new
    assert_kind_of TcpEcn, t
    assert_equal(0, t.to_i)
    t.n = 1
    assert_equal(4, t.to_i)
    t.c = 1
    assert_equal(6, t.to_i)
    t.e = 1
    assert_equal(7, t.to_i)
  end

  def test_ecn_read
    t = TcpEcn.new
    assert_kind_of TcpEcn, t
    t.read("\x30\xc0")
    assert_equal(0, t.n)
    assert_equal(1, t.c)
    assert_equal(1, t.e)
    t.read("\xa3\x38")
    assert_equal(1, t.n)
    assert_equal(0, t.c)
    assert_equal(0, t.e)
  end

  def test_hlen_set
    t = TcpHlen.new
    assert_kind_of TcpHlen, t
    assert_equal(0, t.to_i)
    t.hlen = 10
    assert_equal(10, t.to_i)
  end

  def test_hlen_read
    t = TcpHlen.new
    t.read("\xa0")
    assert_equal(10, t.to_i)
  end

  def test_reserved_set
    t = TcpReserved.new
    assert_kind_of TcpReserved, t
    assert_equal(0, t.to_i)
    t.r1 = 1
    assert_equal(4, t.to_i)
    t.r2 = 1
    assert_equal(6, t.to_i)
    t.r3 = 1
    assert_equal(7, t.to_i)
  end

  def test_reserved_read
    t = TcpReserved.new
    t.read("\xa0")
    assert_equal(0, t.to_i)
  end

end

class TcpFlagsTest < Test::Unit::TestCase
  include PacketFu

  def test_tcp_flags_set
    t = TcpFlags.new
    assert_kind_of TcpFlags, t
    t.fin = 1
    t.ack = 1
    assert_equal(0x11, t.to_i)
    t.fin = 0
    t.syn = 1
    assert_equal(0x12, t.to_i)
  end

  def test_tcp_flags_unset
    t = TcpFlags.new
    assert_kind_of TcpFlags, t
    t.syn = 1
    assert_equal(0x02, t.to_i)
    t.syn = 0
    assert_equal(0x00, t.to_i)
    t.syn = 1
    t.syn = false
    assert_equal(0x00, t.to_i)
  end

  def test_tcp_flags_read
    t = TcpFlags.new
    t.read("\x11")
    assert_equal(1, t.fin)
    assert_equal(1, t.ack)
    t.read("\xa6")
    assert_equal(1, t.urg)
    assert_equal(1, t.rst)
    assert_equal(1, t.syn)
    assert_equal(0, t.psh)
    assert_equal(0, t.ack)
    assert_equal(0, t.fin)
  end

end

class TcpOptionsTest < Test::Unit::TestCase
  include PacketFu

  def test_tcp_option
    t = TcpOption.new
    assert_equal("\x00", t.to_s)
    t = TcpOption.new(:kind => 2, :optlen => 4, :value => 1024)
    assert_equal("\x02\x04\x04\x00", t.to_s)
    t = TcpOption.new(:kind => 0xf0, :optlen => 6, :value => 1024)
    assert_equal("\xf0\x06\x00\x00\x04\x00", t.to_s)
    t = TcpOption.new(:kind => 0xf0, :optlen => 6, :value => "1024")
    assert_equal("\xf0\x061024", t.to_s)
    t = TcpOption.new(:kind => 0xf0, :optlen => 6, :value => nil)
    assert_equal("\xf0\x06", t.to_s)
    t = TcpOption.new(:kind => 0xf1, :optlen => 10, :value => "a1b2c3d4e5")
    assert_equal("\xf1\x0aa1b2c3d4e5", t.to_s)
  end

  def test_eol
    t = TcpOption::EOL.new
    assert_equal("\x00", t.to_s)
    assert_equal(0, t.kind.to_i)
    assert_equal(0, t.kind.value)
    assert_equal(nil, t.optlen.value)
    assert_equal("", t.value)
    assert_equal("EOL",t.decode)
  end

  def test_nop
    t = TcpOption::NOP.new
    assert_equal("\x01", t.to_s)
    assert_equal("NOP",t.decode)
  end

  def test_mss
    t = TcpOption::MSS.new
    t.read("\x02\x04\x05\xb4")
    assert_equal("MSS:1460",t.decode)
    t = TcpOption::MSS.new(:value => 1460)
    assert_equal("\x02\x04\x05\xb4", t.to_s)
    assert_equal("MSS:1460",t.decode)
  end

  def test_sack
    t = TcpOption::SACKOK.new
    assert_equal("\x04\x02", t.to_s)
    assert_equal("SACKOK",t.decode)
  end

  def test_sackok
    t = TcpOption::SACK.new
    assert_equal("\x05\x02", t.to_s)
    assert_equal("SACK:",t.decode)
    t = TcpOption::SACK.new(:value => "ABCD")
    assert_equal("\x05\x06\x41\x42\x43\x44", t.to_s)
    assert_equal("SACK:ABCD",t.decode)
    t = TcpOptions.new
    t.encode("SACK:ABCD,NOP,NOP") # Testing the variable optlen
    assert_equal("SACK:ABCD,NOP,NOP",t.decode)
  end

  def test_echo
    t = TcpOption::ECHO.new(:value => "ABCD")
    assert_equal("\x06\x06\x41\x42\x43\x44", t.to_s)
    assert_equal("ECHO:ABCD",t.decode)
    t = TcpOption::ECHO.new
    t.read("\x06\x06\x41\x42\x43\x44")
    assert_equal("ECHO:ABCD",t.decode)
  end

  def test_echoreply
    t = TcpOption::ECHOREPLY.new(:value => "ABCD")
    assert_equal("\x07\x06\x41\x42\x43\x44", t.to_s)
    assert_equal("ECHOREPLY:ABCD",t.decode)
    t = TcpOption::ECHOREPLY.new
    t.read("\x07\x06\x41\x42\x43\x44")
    assert_equal("ECHOREPLY:ABCD",t.decode)
  end

  def test_tsopt
    t = TcpOption::TS.new
    assert_equal("\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00", t.to_s)
    assert_equal("TS:0;0",t.decode)
  end

  def test_tcpoptions
    opt_string = "0101080a002af12c12ef0d57".bin
    t = TcpOptions.new
    t.read opt_string
    assert_equal("NOP,NOP,TS:2814252;317656407", t.decode)
    assert_equal(opt_string, t.to_s)
    opt_string = "020405b40402080a002af1120000000001030306".bin
    t = TcpOptions.new
    t.read opt_string
    assert_equal("MSS:1460,SACKOK,TS:2814226;0,NOP,WS:6", t.decode)
  end

  def test_tcpoptions_encode
    opt_string = "mss:1460,sackok,ts:2814226;0,nop,ws:6"
    t = TcpOptions.new
    t.encode opt_string
    assert_equal(opt_string.upcase, t.decode)
    assert_kind_of(StructFu::Int8,t[0].kind)
    assert_kind_of(StructFu::Int8,t[0].optlen)
    assert_kind_of(StructFu::Int16,t[0].value)
    assert_equal("\x02\x04\x05\xb4", t[0].to_s)
    assert_equal("\x08\x0a\x00\x2a\xf1\x12\x00\x00\x00\x00", t[2].to_s)
  end

end

class TcpHeaderTest < Test::Unit::TestCase
  include PacketFu

  def test_header_new
    t = TCPHeader.new
    assert_kind_of TCPHeader, t
    assert_equal 20, t.sz
    assert_equal 13, t.size
  end

  def test_header_read
    t = TCPHeader.new
    str = "da920050c9fd6d2b2f54cc2f8018005c74de00000101080a002af11e12ef0d4a".bin
    str << "474554202f20485454502f312e310d0a557365722d4167656e743a206375726c2f372e31382e322028693438362d70632d6c696e75782d676e7529206c69626375726c2f372e31382e32204f70656e53534c2f302e392e3867207a6c69622f312e322e332e33206c696269646e2f312e31300d0a486f73743a207777772e706c616e622d73656375726974792e6e65740d0a4163636570743a202a2f2a0d0a0d0a".bin
    t.read str
    assert_equal 55954, t.tcp_sport
    assert_equal 80, t.tcp_dport
    assert_equal 3388828971, t.tcp_seq
    assert_equal 794086447, t.tcp_ack
    assert_equal 8, t.tcp_hlen
    assert_equal 0, t.tcp_reserved
    assert_equal 0, t.tcp_ecn
    assert_equal 1, t.tcp_flags.psh
    assert_equal 1, t.tcp_flags.ack
    assert_equal 0, t.tcp_flags.syn
    assert_equal 92, t.tcp_win
    assert_equal 0x74de, t.tcp_sum
    assert_equal "NOP,NOP,TS:2814238;317656394", t.tcp_options
    assert_equal "GET /", t.body[0,5]
    assert_equal "*\x0d\x0a\x0d\x0a", t.body[-5,5]
  end

end

class TCPPacketTest < Test::Unit::TestCase
  include PacketFu

  def test_tcp_peek
    t = TCPPacket.new
    t.ip_saddr = "10.20.30.40"
    t.ip_daddr = "50.60.70.80"
    t.tcp_src = 55954
    t.tcp_dport = 80
    t.tcp_flags.syn = 1
    t.tcp_flags.ack = true
    t.payload = "GET / HTTP/1.1\x0d\x0aHost: 50.60.70.80\x0d\x0a\x0d\x0a"
    t.recalc
    puts "\n"
    puts "TCP Peek format: "
    puts t.peek
    assert (t.peek.size <= 80)
  end

  def test_tcp_pcap
    t = TCPPacket.new
    assert_kind_of TCPPacket, t
    t.recalc
    t.to_f('tcp_test.pcap','a')
    t.recalc
    #t.to_f('tcp_test.pcap','a')
    t.ip_saddr = "10.20.30.40"
    t.ip_daddr = "50.60.70.80"
    t.payload = "+some fakey-fake tcp packet"
    t.tcp_sport = 1206
    t.tcp_dst = 13013
    t.tcp_flags.syn = 1
    t.tcp_flags.ack = true
    t.tcp_flags.psh = false
    t.recalc
    #t.to_f('tcp_test.pcap','a')
  end

  def test_tcp_read
    sample_packet = PcapFile.new.file_to_array(:f => 'sample.pcap')[7]
    pkt = Packet.parse(sample_packet)
    assert_kind_of TCPPacket, pkt
    assert_equal(0x5a73, pkt.tcp_sum)
    pkt.to_f('tcp_test.pcap','a') 
  end

  def test_tcp_alter
    sample_packet = PcapFile.new.file_to_array(:f => 'sample2.pcap')[3]
    pkt = Packet.parse(sample_packet)
    assert_kind_of TCPPacket, pkt
    pkt.tcp_sport = 13013
    pkt.payload = pkt.payload.gsub(/planb/,"brandx")
    pkt.recalc
    pkt.to_f('tcp_test.pcap','a')
  end
  
  def test_tcp_read_strip
    str = "e0f8472161a600254ba0760608004500004403554000400651d0c0a83207c0a832370224c1d22d94847f0b07c4ba8018ffff30ba00000101080a8731821433564b8c01027165000000000000200000000000".bin
    str << "0102".bin # Tacking on a couple extra bites tht we'll strip off.
    not_stripped = TCPPacket.new
    not_stripped.read(str)
    assert_equal 18, not_stripped.tcp_header.body.length
    stripped = TCPPacket.new
    stripped.read(str, :strip => true)
    assert_equal 16, stripped.tcp_header.body.length
  end

  def test_tcp_reread
    sample_packet = PacketFu::TCPPacket.new
    pkt = Packet.parse(sample_packet.to_s)
    assert sample_packet.is_tcp?
    assert pkt.is_tcp?
  end

end

class TCPPacketTest < Test::Unit::TestCase
  include PacketFu

  def test_tcp_edit_opts
    t = TCPPacket.new
    assert_equal(0, t.tcp_options.size)
    assert_equal(0, t.tcp_opts_len)
    assert_equal(5, t.tcp_hlen)
    t.tcp_options = "NOP,NOP,NOP,NOP"
    assert_equal(4, t.tcp_opts_len)
    t.recalc
    assert_equal(6, t.tcp_hlen)
  end

end





# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
