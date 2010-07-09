#!/usr/bin/env ruby

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

require 'rex/post/meterpreter/extensions/railgun/tlv'
require "pp"
require 'enumerator'
require 'rex/post/meterpreter/extensions/railgun/api'
require 'rex/post/meterpreter/extensions/railgun/api_constants'

module Rex
	module Post
		module Meterpreter
			module Extensions
				module Railgun

					# Manages our library of windows constants
					class WinConstManager
						def initialize()
							@consts = {}
						end

						def add_const(name, value)
							@consts[name] = value
						end

						# parses a string constaining constants and returns an integer
						# the string can be either "CONST" or "CONST1 | CONST2"
						#
						# this function will NOT throw an exception but return "nil" if it can't parse a string
						def parse(s)
							if s.class != String
								return nil # it's not even a string'
							end
							return_value = 0
							for one_const in s.split('|')
								one_const = one_const.strip()
								if not @consts.has_key? one_const
									return nil # at least one "Constant" is unknown to us
								end
								return_value |= @consts[one_const]
							end
							return return_value
						end

						def is_parseable(s)
							return parse(s) != nil
						end
					end


					# represents one function, e.g. MessageBoxW
					class DLLFunction
						attr_reader :return_type,  :params, :windows_name

						def initialize(return_type, params, windows_name)
							check_return_type(return_type) # we do error checking as early as possible so the library is easier to use
							check_params(params)
							@return_type = return_type
							@params = params
							@windows_name = windows_name
						end

						@@directions=["in", "out", "inout", "return"]
						@@allowed_datatypes={
								"VOID" => ["return"],
								"BOOL" => ["in", "return"],
								"DWORD" => ["in", "return"],
								"WORD" => ["in", "return"],
								"BYTE" => ["in", "return"],
								"PDWORD" => ["in", "out", "inout"],     # todo: support for functions that return pointers to strings
								"PWCHAR" => ["in", "out", "inout"],
								"PCHAR" => ["in", "out", "inout"],
								"PBLOB" => ["in", "out", "inout"]
						}
						private
						def check_type_exists (type)
							if not @@allowed_datatypes.has_key?(type)
								raise "Type unknown: #{type}. Allowed types: #{PP.pp(@@allowed_datatypes.keys, "")}"
							end
						end

						def check_return_type (type)
							check_type_exists(type)
							if not @@allowed_datatypes[type].include?("return")
								raise "#{type} is not allowed as a return type"
							end
						end

						def check_params (params)
							params.each do |param|
								throw "each param must be descriped by a three-tuple [type,name,direction]" unless param.length == 3
								type = param[0]
								direction = param[2]
								check_type_exists(type)
								throw "invalid direction: #{direction}" unless @@directions.include?(direction)
								throw "direction 'return' is only for the return value of the function." unless direction != "return"
							end
						end
					end

					# represents a DLL, e.g. kernel32.dll
					class DLL
						class BufferItem
							attr_reader :belongs_to_param_n, :addr, :length_in_bytes, :datatype

							def initialize(belongs_to_param_n, addr, length_in_bytes, datatype)
								@belongs_to_param_n = belongs_to_param_n
								@addr = addr
								@length_in_bytes = length_in_bytes
								@datatype = datatype
							end
						end

						def initialize(dll_path, client, win_consts) #
							@dll_path = dll_path
							@functions = {}
							@client = client
							@win_consts = win_consts
						end

						# adds a function to the DLL
						# syntax for params:
						# add_function("MessageBoxW",				 # name
						#	"DWORD",								# return value
						#	[["DWORD","hWnd","in"],					 # params
						#	["PWCHAR","lpText","in"],
						#	["PWCHAR","lpCaption","in"],
						#	["DWORD","uType","in"],
						#	])
						#
						# Every function argument is described by a tuple (type,name,direction)
						#
						# windows_name: Use it when the actual windows name is different from the ruby variable
						#               for example when the actual func name is myFunc@4
						#               or when you want to create an alternative version of an existing function
						#
						# When new function is called it will return a list containing the return value and all inout params
						def add_function (name, return_type, params, windows_name=nil)
							if windows_name == nil
								windows_name = name
							end
							@functions[name] = DLLFunction.new(return_type, params, windows_name)
						end

						private

						# parses a DWORD param and returns the value
						# raises an exception if the param cannot be converted to DWORD
						# examples:
						#   3 => 3
						#   "MB_OK" => 0
						#   "SOME_CONSTANT | OTHER_CONSTANT" => 17
						#   "tuna" => !!!!!!!!!!Exception
						def param_to_dword(v)
							if v.class == Fixnum then
								return v # ok, it's already a number
							elsif v.class == Bignum then
								return v # ok, it's already a number
							elsif v.class == String then
								dw = @win_consts.parse(v) # might raise an exception
								if dw != nil
									return dw
								else
									raise "Param #{v} (class #{v.class}) cannot be converted to DWORD. It's a string but matches no constants I know."
								end
							else
								raise "Param #{v} (class #{v.class}) should be a number but isn't"
							end
						end # param_to_dword(v)


						# assembles the buffers "in" and "inout"
						def assemble_buffer (direction, function, args)
							layout = {} # paramName => BufferItem
							blob = ""
							#puts " building buffer: #{direction}"
							function.params.each_with_index do |param_desc, param_idx|
								#puts "  processing #{param_desc[0]} #{param_desc[1]} #{param_desc[2]}"
								# we care only about inout buffers
								if param_desc[2] == direction
									buffer = nil

									# Special case:
									# The user can choose to supply a Null pointer instead of a buffer
									# in this case we don't need space in any heap buffer
									if param_desc[0][0,1] == 'P' # type is a pointer
										if args[param_idx] == nil
											next
										end
									end

									case param_desc[0] # required argument type
										when "PDWORD"
											dw = param_to_dword(args[param_idx])
											buffer = [dw].pack('V')
										when "PWCHAR"
											raise "param #{param_desc[1]}: string expected" unless args[param_idx].class == String
											buffer = str_to_uni_z(args[param_idx])
										when "PCHAR"
											raise "param #{param_desc[1]}: string expected" unless args[param_idx].class == String
											buffer = str_to_ascii_z(args[param_idx])
										when "PBLOB"
											raise "param #{param_desc[1]}: please supply your BLOB as string!" unless args[param_idx].class == String
											buffer = args[param_idx]
										# other types (non-pointers) don't reference buffers
										# and don't need any treatment here
									end
									if buffer != nil
										#puts "   adding #{buffer.length} bytes to heap blob"
										layout[param_desc[1]] = BufferItem.new(param_idx, blob.length, buffer.length, param_desc[0])
										blob += buffer
										#puts "   heap blob size now #{blob.length}"
									end
								end
							end
							#puts "  built buffer: #{direction}"
							return [layout, blob]
						end


						# called when a function like "MessageBoxW" is called
						def process_function_call (function, args)
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
									if param_desc[0] == "PDWORD"
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
										buffer = [0].pack('V') # type: DWORD  (so the dll does not rebase it)
										buffer += [0].pack('V') # value: 0
									elsif param_desc[2] == "in"
										buffer = [1].pack('V')
										buffer += [in_only_layout[param_desc[1]].addr].pack('V')
									elsif param_desc[2] == "out"
										buffer = [2].pack('V')
										buffer += [out_only_layout[param_desc[1]].addr].pack('V')
									elsif param_desc[2] == "inout"
										buffer = [3].pack('V')
										buffer += [inout_layout[param_desc[1]].addr].pack('V')
									else
										raise "unexpected direction"
									end
								else
									#puts "   not a pointer"
									# it's not a pointer
									buffer = [0].pack('V')
									case param_desc[0]
										when "DWORD"
											dw = param_to_dword(args[param_idx])
											buffer += [dw].pack('V')
										when "WORD"
											dw = param_to_dword(args[param_idx])
											buffer += [dw % 65536].pack('V')
										when "BYTE"
											dw = param_to_dword(args[param_idx])
											buffer += [dw % 256].pack('V')
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
							request = Packet.create_request('railgun_api')
							request.add_tlv(TLV_TYPE_RAILGUN_SIZE_OUT, out_only_size_bytes)

							request.add_tlv(TLV_TYPE_RAILGUN_STACKBLOB, literal_pairs_blob)
							request.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_IN, in_only_buffer)
							request.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, inout_buffer)

							request.add_tlv(TLV_TYPE_RAILGUN_DLLNAME, @dll_path )
							request.add_tlv(TLV_TYPE_RAILGUN_FUNCNAME, function.windows_name)


							response = @client.send_request(request)

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
								when "DWORD"
									return_hash["return"] = rec_return_value
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

							return return_hash
						end

						# process_function_call

						# we fake having methods like "MessageBoxW" by intercepting "method-not-found"-exceptions
						def method_missing(func_symbol, *args)
							func_name = func_symbol.to_s
							raise "DLL-function #{func_name} not found. Known functions: #{PP.pp(@functions.keys, "")}" unless @functions.has_key? func_name
							function = @functions[func_name]
							return process_function_call(function, args)
						end

						# converts ruby string to zero-terminated ASCII string
						def str_to_ascii_z (str)
							return str+"\x00"
						end

						# converts 0-terminated ASCII string to ruby string
						def asciiz_to_str(asciiz)
							zero_byte_idx = asciiz.index("\x00")
							if zero_byte_idx != nil
								return asciiz[0, zero_byte_idx]
							else
								return asciiz
							end
						end

						# converts ruby string to zero-terminated WCHAR string
						def str_to_uni_z(str)
							enc = str.unpack("C*").pack("v*")
							enc += "\x00\x00"
							return enc
						end

						# converts 0-terminated UTF16 to ruby string
						def uniz_to_str(uniz)
							uniz.unpack("v*").pack("C*").unpack("A*")[0]
						end
					end

					#
					# This extensions give you access to the full Windows API
					#
					class Railgun < Extension
						def initialize(client)
							super(client, 'railgun')
							@client = client
							@dll = {}
							@win_consts = WinConstManager.new()

							# Load tons of definitions
							ApiDefinitions.add_imports(self)
							ApiConstants.add_constants(@win_consts)

							client.register_extension_aliases(
									[
											{
													'name' => 'railgun',
													'ext' => self
											},
									])
						end

						# adds a function to an existing DLL-definition
						def add_function (dll_name, function_name, return_type, params, windows_name=nil)
							raise "DLL #{dll_name} not found. Known DLLs: #{PP.pp(@dll.keys, "")}" unless @dll.has_key? dll_name
							@dll[dll_name].add_function(function_name, return_type, params, windows_name)
						end

						# adds a function to an existing DLL-definition
						# you can override the dll name if you want to include a path or the DLL name contains
						# non-ruby-approved characters
						def add_dll(dll_name, windows_name=nil)
							raise "DLL #{dll_name} already exists. Existing DLLs: #{PP.pp(@dll.keys, "")}" unless not @dll.has_key? dll_name
							if windows_name == nil
								windows_name = dll_name
							end
							@dll[dll_name] = DLL.new(windows_name, @client, @win_consts)
						end

						# we fake having members like user32 and kernel32.
						# reason is that
						#   ...user32.MessageBoxW()
						# is prettier than
						#   ...dlls["user32"].functions["MessageBoxW"]()
						def method_missing(dll_symbol, *args)
							dll_name = dll_symbol.to_s
							raise "DLL #{dll_name} not found. Known DLLs: #{PP.pp(@dll.keys, "")}" unless @dll.has_key? dll_name
							return @dll[dll_name]
						end

						# Give the programmer access to constants
						def const(str)
							return @win_consts.parse(str)
						end
					end

				end;
			end;
		end;
	end;
end;

