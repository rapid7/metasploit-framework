# -*- coding: binary -*-

module Rex
module Proto
##
#
# Quake 3 protocol, taken from ftp://ftp.idsoftware.com/idstuff/quake3/docs/server.txt
#
##
module Quake
  HEADER = 0xFFFFFFFF

  def decode_message(message)
    # minimum size is header (4) + <command> + <stuff>
    return if message.length < 7
    header = message.unpack('N')[0]
    return if header != HEADER
    message[4, message.length]
  end

  def encode_message(payload)
    [HEADER].pack('N') + payload
  end

  def getstatus
    encode_message('getstatus')
  end

  def getinfo
    encode_message('getinfo')
  end

  def decode_infostring(infostring)
    # decode an "infostring", which is just a (supposedly) quoted string of tokens separated
    # by backslashes, generally terminated with a newline
    token_re = /([^\\]+)\\([^\\]+)/
    return nil unless infostring =~ token_re
    # remove possibly present leading/trailing double quote
    infostring.gsub!(/(?:^"|"$)/, '')
    # remove the trailing \n, if present
    infostring.gsub!(/\n$/, '')
    # split on backslashes and group into key value pairs
    infohash = {}
    infostring.scan(token_re).each do |kv|
      infohash[kv.first] = kv.last
    end
    infohash
  end

  def decode_response(message, type)
    resp = decode_message(message)
    if /^print\n(?<error>.*)\n?/m =~ resp
      # XXX: is there a better exception to throw here?
      fail ::ArgumentError, "#{type} error: #{error}"
    # why doesn't this work?
    # elsif /^#{type}Response\n(?<infostring>.*)/m =~ resp
    elsif resp =~ /^#{type}Response\n(.*)/m
      decode_infostring(Regexp.last_match(1))
    else
      nil
    end
  end

  def decode_status(message)
    decode_response(message, 'status')
  end

  def decode_info(message)
    decode_response(message, 'info')
  end
end
end
end
