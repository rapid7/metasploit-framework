# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/bofloader/tlv'
require 'rex/post/meterpreter/extensions/bofloader/command_ids'
require 'rexml/document'
require 'set'

module Rex
module Post
module Meterpreter
module Extensions
module Bofloader

###
#
# Bofloader extension - Executes a beacon object file in
# the current meterpreter session.
#
# Kevin Haubris (@kev169)
# Kevin Clark (@GuhnooPlusLinux)
# TrustedSec (@TrustedSec)
#
###

class BofPack
  # Code referenced from: https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py
  # Emulates the native Cobalt Strike bof_pack() function.
  # Documented here: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
  #
  # Type      Description                             Unpack With (C)
  # --------|---------------------------------------|------------------------------
  # b       | binary data                           | BeaconDataExtract
  # i       | 4-byte integer                        | BeaconDataInt
  # s       | 2-byte short integer                  | BeaconDataShort
  # z       | zero-terminated+encoded string        | BeaconDataExtract
  # Z       | zero-terminated wide-char string      | (wchar_t *)BeaconDataExtract

  def initialize()
    @buffer = ''
    @size = 0
  end

  def addshort(short)
    @buffer << [short.to_i].pack("<s")
    @size += 2
  end

  def addint(dint)
    @buffer << [dint.to_i].pack("<I")
    @size += 4
  end

  def addstr(s)
    s = s.encode("utf-8").bytes
    s << 0x00 # Null terminated strings...
    s_length = s.length
    s = [s_length] + s
    buf = s.pack("<Ic#{s_length}")
    @size += buf.length
    @buffer << buf
  end

  def addWstr(s)
    s = s.encode("utf-16le").bytes
    s << 0x00 << 0x00 # Null terminated wide string
    s_length = s.length
    s = [s_length] + s
    buf = s.pack("<Ic#{s_length}")
    @size += buf.length
    @buffer << buf
  end

  def addbinary(b)
    # Add binary data to the buffer
    if b.class != "Array"
      b = b.bytes
    end
    b << 0x00 # Null terminated binary data
    b_length = b.length
    b = [b_length] + b
    buf = b.pack("<Ic#{b_length}")
    @size += buf.length
    @buffer << buf
  end

  def finalize_buffer()
    output = [@size].pack("<I") + @buffer
    initialize() # Reset the class' buffer for another round
    return output
  end

  def bof_pack(fstring, args)
    # Wrapper function to pack an entire bof command line into a buffer
    if fstring.nil? or args.nil?
      return finalize_buffer()
    end

    fstring.each_char.each_with_index do |c,i|
      if c == "b"
        addbinary(args[i])
      elsif c == "i"
        addint(args[i])
      elsif c == "s"
        addshort(args[i])
      elsif c == "z"
        addstr(args[i])
      elsif c == "Z"
        addWstr(args[i])
      else
        raise "Invalid character in format string: #{c}. Must be one of \"b, i, s, z, Z\""
      end
    end

    # return the packed bof_string
    finalize_buffer
  end
end

class Bofloader < Extension

  def self.extension_id
    EXTENSION_ID_BOFLOADER
  end

  # Typical extension initialization routine.
  #
  # @param client (see Extension#initialize)
  def initialize(client)
    super(client, 'bofloader')

    client.register_extension_aliases(
      [
        {
          'name' => 'bofloader',
          'ext'  => self
        },
      ])

  end

  def execute(bof_data, args_format: nil, args: nil, entry: 'go')
    request = Packet.create_request(COMMAND_ID_BOFLOADER_EXECUTE)

    # Pack up beacon object file data and arguments into one single binary blob
    # Hardcode the entrypoint to "go" (CobaltStrike approved)
    bof = BofPack.new
    packed_args = bof.bof_pack(args_format, args)

    # Send the meterpreter TLV packet and get the output back
    request.add_tlv(TLV_TYPE_BOFLOADER_EXECUTE_BUFFER, bof_data)
    request.add_tlv(TLV_TYPE_BOFLOADER_EXECUTE_BUFFER_ENTRY, entry)
    request.add_tlv(TLV_TYPE_BOFLOADER_EXECUTE_ARGUMENTS, packed_args)
    response = client.send_request(request)
    return response.get_tlv_value(TLV_TYPE_BOFLOADER_EXECUTE_RESULT)
  end

end

end; end; end; end; end
