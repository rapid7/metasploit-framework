# -*- coding: binary -*-
# Copyright (c) 2010, patrickHVE@googlemail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * The names of the author may not be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL patrickHVE@googlemail.com BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'rex/post/meterpreter/extensions/stdapi/railgun/library_function'
require 'rex/post/meterpreter/extensions/stdapi/railgun/library_helper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/buffer_item'
require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'
require 'rex/post/meterpreter/packet'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

#
# Represents a library, e.g. kernel32.dll
#
class Library

  include LibraryHelper

  @@datatype_map = {
    'HANDLE'  => 'LPVOID',
    # really should be PVOID* but LPVOID is handled specially with the 'L' prefix to *not* treat it as a pointer, and
    # for railgun's purposes LPVOID == ULONG_PTR
    'PHANDLE' => 'PULONG_PTR',
    'SIZE_T'  => 'ULONG_PTR',
    'PSIZE_T' => 'PULONG_PTR',
  }.freeze

  attr_accessor :functions
  attr_reader   :library_path

  def initialize(library_path, consts_mgr)
    @library_path = library_path

    # needed by LibraryHelper
    @consts_mgr = consts_mgr

    self.functions = {}
  end

  def known_function_names
    return functions.keys
  end

  def get_function(name)
    return functions[name]
  end

  #
  # Perform a function call in this library on the remote system.
  #
  # Returns a Hash containing the return value, the result of GetLastError(),
  # and any +inout+ parameters.
  #
  # Raises an exception if +function+ is not a known function in this library,
  # i.e., it hasn't been defined in a Def.
  #
  def call_function(function, args, client)
    unless function.instance_of? LibraryFunction
      func_name = function.to_s

      unless known_function_names.include? func_name
        raise "Library-function #{func_name} not found. Known functions: #{PP.pp(known_function_names, '')}"
      end

      function = get_function(func_name)
    end

    return process_function_call(function, args, client)
  end

  #
  # Define a function for this library.
  #
  # Every function argument is described by a tuple (type,name,direction)
  #
  # Example:
  #   add_function("MessageBoxW",   # name
  #     "DWORD",                    # return value
  #     [                           # params
  #	   ["DWORD","hWnd","in"],
  #      ["PWCHAR","lpText","in"],
  #      ["PWCHAR","lpCaption","in"],
  #      ["DWORD","uType","in"],
  #     ])
  #
  # Use +remote_name+ when the actual library name is different from the
  # ruby variable.  You might need to do this for example when the actual
  # func name is myFunc@4 or when you want to create an alternative version
  # of an existing function.
  #
  # When the new function is called it will return a list containing the
  # return value and all inout params.  See #call_function.
  #
  def add_function(name, return_type, params, remote_name=nil, calling_conv='stdcall')
    return_type = reduce_type(return_type)
    params = reduce_parameter_types(params)
    if remote_name == nil
      remote_name = name
    end
    @functions[name] = LibraryFunction.new(return_type, params, remote_name, calling_conv)
  end

  def build_packet_and_layouts(packet, function, args, arch)
    case arch
    when ARCH_X64
      native = 'Q<'
    when ARCH_X86
      native = 'V'
    else
      raise NotImplementedError, 'Unsupported architecture (must be ARCH_X86 or ARCH_X64)'
    end

    # We transmit the immediate stack and three heap-buffers:
    # in, inout and out. The reason behind the separation is bandwidth.
    # We don't want to transmit uninitialized data in or no-longer-needed data out.

    # out-only-buffers that are ONLY transmitted on the way BACK
    out_only_layout = {} # paramName => BufferItem
    out_only_size_bytes = 0
    #puts " assembling out-only buffer"
    function.params.each_with_index do |param_desc, param_idx|
      #puts " processing #{param_desc[1]}"

      # Special case:
      # The user can choose to supply a Null pointer instead of a buffer
      # in this case we don't need space in any heap buffer
      if param_desc[0][0,1] == 'P' # type is a pointer (except LPVOID where the L negates this)
        if args[param_idx] == nil
          next
        end
      end

      # we care only about out-only buffers
      if param_desc[2] == 'out'
        if !args[param_idx].kind_of? Integer
          raise "error in param #{param_desc[1]}: Out-only buffers must be described by a number indicating their size in bytes"
        end
        buffer_size = args[param_idx]
        if param_desc[0] == 'PULONG_PTR'
          # bump up the size for an x64 pointer
          if arch == ARCH_X64 && buffer_size == 4
            buffer_size = args[param_idx] = 8
          end

          if arch == ARCH_X64
            if buffer_size != 8
              raise "Please pass 8 for 'out' PULONG_PTR, since they require a buffer of size 8"
            end
          elsif arch == ARCH_X86
            if buffer_size != 4
              raise "Please pass 4 for 'out' PULONG_PTR, since they require a buffer of size 4"
            end
          end
        end

        out_only_layout[param_desc[1]] = BufferItem.new(param_idx, out_only_size_bytes, buffer_size, param_desc[0])
        out_only_size_bytes += buffer_size
      end
    end

    in_only_layout, in_only_buffer = assemble_buffer('in', function, args, arch)
    inout_layout, inout_buffer = assemble_buffer('inout', function, args, arch)

    # now we build the stack
    # every stack dword will be described by two dwords:
    # first dword describes second dword:
    #	0 - literal,
    #	1 = relative to in-only buffer
    #	2 = relative to out-only buffer
    #	3 = relative to inout buffer

    # (literal numbers and pointers to buffers we have created)
    literal_pairs_blob = ""
    #puts " assembling literal stack"
    function.params.each_with_index do |param_desc, param_idx|
      #puts "  processing (#{param_desc[0]}, #{param_desc[1]}, #{param_desc[2]})"
      buffer = nil
      # is it a pointer to a buffer on our stack
      if ['PULONG_PTR', 'PDWORD', 'PWCHAR', 'PCHAR', 'PBLOB'].include? param_desc[0]
        #puts '   pointer'
        if args[param_idx] == nil # null pointer?
          buffer  = [0].pack(native) # type: DWORD  (so the library does not rebase it)
          buffer += [0].pack(native) # value: 0
        elsif param_desc[2] == 'in'
          buffer  = [1].pack(native)
          buffer += [in_only_layout[param_desc[1]].addr].pack(native)
        elsif param_desc[2] == 'out'
          buffer  = [2].pack(native)
          buffer += [out_only_layout[param_desc[1]].addr].pack(native)
        elsif param_desc[2] == 'inout'
          buffer  = [3].pack(native)
          buffer += [inout_layout[param_desc[1]].addr].pack(native)
        else
          raise 'unexpected direction'
        end
      else
        #puts "   not a pointer"
        # it's not a pointer (LPVOID is a pointer but is not backed by railgun memory, ala PBLOB)
        buffer = [0].pack(native)
        case param_desc[0]
          when 'LPVOID', 'ULONG_PTR'
            num     = param_to_number(args[param_idx])
            buffer += [num].pack(native)
          when 'DWORD'
            num     = param_to_number(args[param_idx])
            buffer += [num & 0xffffffff].pack(native)
          when 'WORD'
            num     = param_to_number(args[param_idx])
            buffer += [num & 0xffff].pack(native)
          when 'BYTE'
            num     = param_to_number(args[param_idx])
            buffer += [num & 0xff].pack(native)
          when 'BOOL'
            case args[param_idx]
              when true
                buffer += [1].pack(native)
              when false
                buffer += [0].pack(native)
              else
                raise "param #{param_desc[1]}: true or false expected"
            end
          else
            raise "unexpected type for param #{param_desc[1]}"
        end
      end

      #puts "   adding pair to blob"
      literal_pairs_blob += buffer
      #puts "   buffer size %X" % buffer.length
      #puts "   blob size so far: %X" % literal_pairs_blob.length
    end

    layouts = {in: in_only_layout, inout: inout_layout, out: out_only_layout}

    packet.add_tlv(TLV_TYPE_RAILGUN_SIZE_OUT, out_only_size_bytes)
    packet.add_tlv(TLV_TYPE_RAILGUN_STACKBLOB, literal_pairs_blob)
    packet.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_IN, in_only_buffer)
    packet.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, inout_buffer)

    packet.add_tlv(TLV_TYPE_RAILGUN_LIBNAME, @library_path)
    packet.add_tlv(TLV_TYPE_RAILGUN_FUNCNAME, function.remote_name)
    packet.add_tlv(TLV_TYPE_RAILGUN_CALLCONV, function.calling_conv)
    [packet, layouts]
  end

  def build_response(packet, function, layouts, arch)
    case arch
    when ARCH_X64
      native = 'Q<'
    when ARCH_X86
      native = 'V'
    else
      raise NotImplementedError, 'Unsupported architecture (must be ARCH_X86 or ARCH_X64)'
    end

    rec_inout_buffers = packet.get_tlv_value(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT)
    rec_out_only_buffers = packet.get_tlv_value(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT)
    rec_return_value = packet.get_tlv_value(TLV_TYPE_RAILGUN_BACK_RET)
    rec_last_error = packet.get_tlv_value(TLV_TYPE_RAILGUN_BACK_ERR)
    rec_err_msg = packet.get_tlv_value(TLV_TYPE_RAILGUN_BACK_MSG)

    # Error messages come back with trailing CRLF, so strip it out if we do get a message.
    rec_err_msg.strip! unless rec_err_msg.nil?

    # the hash the function returns
    return_hash = {
      'GetLastError' => rec_last_error,
      'ErrorMessage' => rec_err_msg
    }

    # process return value
    case function.return_type
      when 'LPVOID', 'ULONG_PTR'
        if arch == ARCH_X64
          return_hash['return'] = rec_return_value
        else
          return_hash['return'] = rec_return_value & 0xffffffff
        end
      when 'DWORD'
        return_hash['return'] = rec_return_value & 0xffffffff
      when 'WORD'
        return_hash['return'] = rec_return_value & 0xffff
      when 'BYTE'
        return_hash['return'] = rec_return_value & 0xff
      when 'BOOL'
        return_hash['return'] = (rec_return_value != 0)
      when 'VOID'
        return_hash['return'] = nil
      else
        raise "unexpected return type: #{function.return_type}"
    end

    # process out-only buffers
    layouts[:out].each_pair do |param_name, buffer_item|
      buffer = rec_out_only_buffers[buffer_item.addr, buffer_item.length_in_bytes]
      case buffer_item.datatype
        when 'PULONG_PTR'
          return_hash[param_name] = buffer.unpack(native).first
        when 'PDWORD'
          return_hash[param_name] = buffer.unpack('V').first
        when 'PCHAR'
          return_hash[param_name] = asciiz_to_str(buffer)
        when 'PWCHAR'
          return_hash[param_name] = uniz_to_str(buffer)
        when 'PBLOB'
          return_hash[param_name] = buffer
        else
          raise "unexpected type in out-only buffer of #{param_name}: #{buffer_item.datatype}"
      end
    end

    # process in-out buffers
    layouts[:inout].each_pair do |param_name, buffer_item|
      buffer = rec_inout_buffers[buffer_item.addr, buffer_item.length_in_bytes]
      case buffer_item.datatype
        when 'PULONG_PTR'
          return_hash[param_name] = buffer.unpack(native).first
        when 'PDWORD'
          return_hash[param_name] = buffer.unpack('V').first
        when 'PCHAR'
          return_hash[param_name] = asciiz_to_str(buffer)
        when 'PWCHAR'
          return_hash[param_name] = uniz_to_str(buffer)
        when 'PBLOB'
          return_hash[param_name] = buffer
        else
          raise "unexpected type in in-out-buffer of #{param_name}: #{buffer_item.datatype}"
      end
    end

    return_hash
  end

  private

  def process_function_call(function, args, client)
    raise "#{function.params.length} arguments expected. #{args.length} arguments provided." unless args.length == function.params.length

    request, layouts = build_packet_and_layouts(
      Packet.create_request(COMMAND_ID_STDAPI_RAILGUN_API),
      function,
      args,
      client.native_arch
    )

    response = client.send_request(request)

    build_response(response, function, layouts, client.native_arch)
  end

  # perform type conversions as necessary to reduce the datatypes to their primitives
  def reduce_parameter_types(params)
    params.each_with_index do |param, idx|
      type, name, direction = param
      params[idx] = [reduce_type(type), name, direction]
    end

    params
  end

  def reduce_type(datatype)
    while @@datatype_map.key?(datatype)
      datatype = @@datatype_map[datatype]
    end

    datatype
  end
end

end; end; end; end; end; end;
