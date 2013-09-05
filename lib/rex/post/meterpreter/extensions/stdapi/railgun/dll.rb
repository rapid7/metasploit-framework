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

require 'rex/post/meterpreter/extensions/stdapi/railgun/dll_helper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/dll_function'
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
# Represents a DLL, e.g. kernel32.dll
#
class DLL

  include DLLHelper

  attr_accessor :functions
  attr_reader   :dll_path

  def initialize(dll_path, win_consts)
    @dll_path = dll_path

    # needed by DLLHelper
    @win_consts = win_consts

    self.functions = {}
  end

  def known_function_names
    return functions.keys
  end

  def get_function(name)
    return functions[name]
  end

  #
  # Perform a function call in this DLL on the remote system.
  #
  # Returns a Hash containing the return value, the result of GetLastError(),
  # and any +inout+ parameters.
  #
  # Raises an exception if +func_symbol+ is not a known function in this DLL,
  # i.e., it hasn't been defined in a Def.
  #
  def call_function(func_symbol, args, client)
    func_name = func_symbol.to_s

    unless known_function_names.include? func_name
      raise "DLL-function #{func_name} not found. Known functions: #{PP.pp(known_function_names, '')}"
    end

    function = get_function(func_name)

    return process_function_call(function, args, client)
  end

  #
  # Define a function for this DLL.
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
  # Use +windows_name+ when the actual windows name is different from the
  # ruby variable.  You might need to do this for example when the actual
  # func name is myFunc@4 or when you want to create an alternative version
  # of an existing function.
  #
  # When the new function is called it will return a list containing the
  # return value and all inout params.  See #call_function.
  #
  def add_function(name, return_type, params, windows_name=nil, calling_conv="stdcall")
    if windows_name == nil
      windows_name = name
    end
    @functions[name] = DLLFunction.new(return_type, params, windows_name, calling_conv)
  end

  private

  def process_function_call(function, args, client)
    raise "#{function.params.length} arguments expected. #{args.length} arguments provided." unless args.length == function.params.length

    if( client.platform =~ /x64/i )
      native = 'Q'
    else
      native = 'V'
    end

#puts "process_function_call(function.windows_name,#{PP.pp(args, "")})"

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
      if param_desc[0][0,1] == 'P' # type is a pointer
        if args[param_idx] == nil
          next
        end
      end

      # we care only about out-only buffers
      if param_desc[2] == "out"
        raise "error in param #{param_desc[1]}: Out-only buffers must be described by a number indicating their size in bytes " unless args[param_idx].class == Fixnum
        buffer_size = args[param_idx]
        if param_desc[0] == "PDWORD"
          # bump up the size for an x64 pointer
          if( native == 'Q' and buffer_size == 4 )
            args[param_idx] = 8
            buffer_size = args[param_idx]
          end

          if( native == 'Q' )
            raise "Please pass 8 for 'out' PDWORDS, since they require a buffer of size 8" unless buffer_size == 8
          elsif( native == 'V' )
            raise "Please pass 4 for 'out' PDWORDS, since they require a buffer of size 4" unless buffer_size == 4
          end
        end

        out_only_layout[param_desc[1]] = BufferItem.new(param_idx, out_only_size_bytes, buffer_size, param_desc[0])
        out_only_size_bytes += buffer_size
      end
    end

    tmp = assemble_buffer("in", function, args)
    in_only_layout = tmp[0]
    in_only_buffer = tmp[1]

    tmp = assemble_buffer("inout", function, args)
    inout_layout = tmp[0]
    inout_buffer = tmp[1]

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
      if ["PDWORD", "PWCHAR", "PCHAR", "PBLOB"].include? param_desc[0]
        #puts "   pointer"
        if args[param_idx] == nil # null pointer?
          buffer  = [0].pack(native) # type: DWORD  (so the dll does not rebase it)
          buffer += [0].pack(native) # value: 0
        elsif param_desc[2] == "in"
          buffer  = [1].pack(native)
          buffer += [in_only_layout[param_desc[1]].addr].pack(native)
        elsif param_desc[2] == "out"
          buffer  = [2].pack(native)
          buffer += [out_only_layout[param_desc[1]].addr].pack(native)
        elsif param_desc[2] == "inout"
          buffer  = [3].pack(native)
          buffer += [inout_layout[param_desc[1]].addr].pack(native)
        else
          raise "unexpected direction"
        end
      else
        #puts "   not a pointer"
        # it's not a pointer (LPVOID is a pointer but is not backed by railgun memory, ala PBLOB)
        buffer = [0].pack(native)
        case param_desc[0]
          when "LPVOID", "HANDLE"
            num     = param_to_number(args[param_idx])
            buffer += [num].pack(native)
          when "DWORD"
            num     = param_to_number(args[param_idx])
            buffer += [num % 4294967296].pack(native)
          when "WORD"
            num     = param_to_number(args[param_idx])
            buffer += [num % 65536].pack(native)
          when "BYTE"
            num     = param_to_number(args[param_idx])
            buffer += [num % 256].pack(native)
          when "BOOL"
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

    #puts "\n\nsending Stuff to meterpreter"
    request = Packet.create_request('stdapi_railgun_api')
    request.add_tlv(TLV_TYPE_RAILGUN_SIZE_OUT, out_only_size_bytes)

    request.add_tlv(TLV_TYPE_RAILGUN_STACKBLOB, literal_pairs_blob)
    request.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_IN, in_only_buffer)
    request.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, inout_buffer)

    request.add_tlv(TLV_TYPE_RAILGUN_DLLNAME, @dll_path )
    request.add_tlv(TLV_TYPE_RAILGUN_FUNCNAME, function.windows_name)
    request.add_tlv(TLV_TYPE_RAILGUN_CALLCONV, function.calling_conv)

    response = client.send_request(request)

    #puts "receiving Stuff from meterpreter"
    #puts "out_only_layout:"
    #puts out_only_layout

    rec_inout_buffers = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT)
    rec_out_only_buffers = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT)
    rec_return_value = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_RET)
    rec_last_error = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_ERR)

    #puts "received stuff"
    #puts "out_only_layout:"
    #puts out_only_layout

    # The hash the function returns
    return_hash={"GetLastError" => rec_last_error}

    #process return value
    case function.return_type
      when "LPVOID", "HANDLE"
        if( native == 'Q' )
          return_hash["return"] = rec_return_value
        else
          return_hash["return"] = rec_return_value % 4294967296
        end
      when "DWORD"
        return_hash["return"] = rec_return_value % 4294967296
      when "WORD"
        return_hash["return"] = rec_return_value % 65536
      when "BYTE"
        return_hash["return"] = rec_return_value % 256
      when "BOOL"
        return_hash["return"] = (rec_return_value != 0)
      when "VOID"
        return_hash["return"] = nil
      else
        raise "unexpected return type: #{function.return_type}"
    end
    #puts return_hash
    #puts "out_only_layout:"
    #puts out_only_layout


    # process out-only buffers
    #puts "processing out-only buffers:"
    out_only_layout.each_pair do |param_name, buffer_item|
      #puts "   #{param_name}"
      buffer = rec_out_only_buffers[buffer_item.addr, buffer_item.length_in_bytes]
      case buffer_item.datatype
        when "PDWORD"
          return_hash[param_name] = buffer.unpack('V')[0]
        when "PCHAR"
          return_hash[param_name] = asciiz_to_str(buffer)
        when "PWCHAR"
          return_hash[param_name] = uniz_to_str(buffer)
        when "PBLOB"
          return_hash[param_name] = buffer
        else
          raise "unexpected type in out-only buffer of #{param_name}: #{buffer_item.datatype}"
      end
    end
    #puts return_hash

    # process in-out buffers
    #puts "processing in-out buffers:"
    inout_layout.each_pair do |param_name, buffer_item|
      #puts "   #{param_name}"
      buffer = rec_inout_buffers[buffer_item.addr, buffer_item.length_in_bytes]
      case buffer_item.datatype
        when "PDWORD"
          return_hash[param_name] = buffer.unpack('V')[0]
        when "PCHAR"
          return_hash[param_name] = asciiz_to_str(buffer)
        when "PWCHAR"
          return_hash[param_name] = uniz_to_str(buffer)
        when "PBLOB"
          return_hash[param_name] = buffer
        else
          raise "unexpected type in in-out-buffer of #{param_name}: #{buffer_item.datatype}"
      end
    end
    #puts return_hash

    #puts "finished"
#		puts("
#=== START of proccess_function_call snapshot ===
#		{
#			:platform => '#{native == 'Q' ? 'x64/win64' : 'x86/win32'}',
#			:name => '#{function.windows_name}',
#			:params => #{function.params},
#			:return_type => '#{function.return_type}',
#			:dll_name => '#{@dll_path}',
#			:ruby_args => #{args.inspect},
#			:request_to_client => {
#				TLV_TYPE_RAILGUN_SIZE_OUT => #{out_only_size_bytes},
#				TLV_TYPE_RAILGUN_STACKBLOB => #{literal_pairs_blob.inspect},
#				TLV_TYPE_RAILGUN_BUFFERBLOB_IN => #{in_only_buffer.inspect},
#				TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => #{inout_buffer.inspect},
#				TLV_TYPE_RAILGUN_DLLNAME => '#{@dll_path}',
#				TLV_TYPE_RAILGUN_FUNCNAME => '#{function.windows_name}',
#			},
#			:response_from_client => {
#				TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => #{rec_inout_buffers.inspect},
#				TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => #{rec_out_only_buffers.inspect},
#				TLV_TYPE_RAILGUN_BACK_RET => #{rec_return_value.inspect},
#				TLV_TYPE_RAILGUN_BACK_ERR => #{rec_last_error},
#			},
#			:returned_hash => #{return_hash.inspect},
#		},
#=== END of proccess_function_call snapshot ===
#		")
#
    return return_hash
  end

end

end; end; end; end; end; end;
