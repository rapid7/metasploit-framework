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

require 'pp'
require 'enumerator'
require 'rex/post/meterpreter/extensions/stdapi/railgun/api_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'
require 'rex/post/meterpreter/extensions/stdapi/railgun/dll_helper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/buffer_item'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

# A easier way to call multiple functions in a single request
class MultiCaller

    include DLLHelper

    def initialize( client, parent )
      @parent = parent
      @client = client

      if( @client.platform =~ /x64/i )
        @native = 'Q'
      else
        @native = 'V'
      end
    end

    def call(functions)

      request = Packet.create_request('stdapi_railgun_api_multi')
      function_results = []
      layouts          = []
      functions.each do |f|
        dll_name,funcname,args = f
        dll_host = @parent.get_dll( dll_name )

        if not dll_host
          raise "DLL #{dll_name} has not been loaded"
        end

        function = dll_host.functions[funcname]
        if not function
          raise "DLL #{dll_name} function #{funcname} has not been defined"
        end

        raise "#{function.params.length} arguments expected. #{args.length} arguments provided." unless args.length == function.params.length
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
            # bump up the size for an x64 pointer
            if( @native == 'Q' and buffer_size == 4 )
              args[param_idx] = 8
              buffer_size = args[param_idx]
            end

            if( @native == 'Q' )
              raise "Please pass 8 for 'out' PDWORDS, since they require a buffer of size 8" unless buffer_size == 8
            elsif( @native == 'V' )
              raise "Please pass 4 for 'out' PDWORDS, since they require a buffer of size 4" unless buffer_size == 4
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
              buffer = [0].pack(@native) # type: DWORD  (so the dll does not rebase it)
              buffer += [0].pack(@native) # value: 0
            elsif param_desc[2] == "in"
              buffer = [1].pack(@native)
              buffer += [in_only_layout[param_desc[1]].addr].pack(@native)
            elsif param_desc[2] == "out"
              buffer = [2].pack(@native)
              buffer += [out_only_layout[param_desc[1]].addr].pack(@native)
            elsif param_desc[2] == "inout"
              buffer = [3].pack(@native)
              buffer += [inout_layout[param_desc[1]].addr].pack(@native)
            else
              raise "unexpected direction"
            end
          else
            #puts "   not a pointer"
            # it's not a pointer
            buffer = [0].pack(@native)
            case param_desc[0]
              when "LPVOID", "HANDLE"
                num     = param_to_number(args[param_idx])
                buffer += [num].pack(@native)
              when "DWORD"
                num     = param_to_number(args[param_idx])
                buffer += [num % 4294967296].pack(@native)
              when "WORD"
                num     = param_to_number(args[param_idx])
                buffer += [num % 65536].pack(@native)
              when "BYTE"
                num     = param_to_number(args[param_idx])
                buffer += [num % 256].pack(@native)
              when "BOOL"
                case args[param_idx]
                  when true
                    buffer += [1].pack('V')
                  when false
                    buffer += [0].pack('V')
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

        group = Rex::Post::Meterpreter::GroupTlv.new(TLV_TYPE_RAILGUN_MULTI_GROUP)
        group.add_tlv(TLV_TYPE_RAILGUN_SIZE_OUT, out_only_size_bytes)
        group.add_tlv(TLV_TYPE_RAILGUN_STACKBLOB, literal_pairs_blob)
        group.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_IN, in_only_buffer)
        group.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, inout_buffer)
        group.add_tlv(TLV_TYPE_RAILGUN_DLLNAME, dll_name )
        group.add_tlv(TLV_TYPE_RAILGUN_FUNCNAME, function.windows_name)
        request.tlvs << group

        layouts << [inout_layout, out_only_layout]
      end

      call_results = []
      res = @client.send_request(request)
      res.each(TLV_TYPE_RAILGUN_MULTI_GROUP) do |val|
        call_results << val
      end

      functions.each do |f|
        dll_name,funcname,args = f
        dll_host = @parent.get_dll( dll_name )
        function = dll_host.functions[funcname]
        response = call_results.shift
        inout_layout, out_only_layout = layouts.shift

        rec_inout_buffers = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT)
        rec_out_only_buffers = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT)
        rec_return_value = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_RET)
        rec_last_error = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_ERR)

        # The hash the function returns
        return_hash={"GetLastError" => rec_last_error}

        #process return value
        case function.return_type
          when "LPVOID", "HANDLE"
            if( @native == 'Q' )
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

        function_results << return_hash
      end
      function_results
    end
    # process_multi_function_call

  protected

  attr_accessor :win_consts

end # MultiCall

end; end; end; end; end; end
