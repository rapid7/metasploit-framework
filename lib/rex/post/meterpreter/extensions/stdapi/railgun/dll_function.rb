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

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

#
# represents one function, e.g. MessageBoxW
#
class DLLFunction
	@@allowed_datatypes = {
		"VOID"   => ["return"],
		"BOOL"   => ["in", "return"],
		"DWORD"  => ["in", "return"],
		"WORD"   => ["in", "return"],
		"BYTE"   => ["in", "return"],
		"LPVOID" => ["in", "return"], # sf: for specifying a memory address (e.g. VirtualAlloc/HeapAlloc/...) where we dont want ot back it up with actuall mem ala PBLOB
		"HANDLE" => ["in", "return"],
		"PDWORD" => ["in", "out", "inout"], # todo: support for functions that return pointers to strings
		"PWCHAR" => ["in", "out", "inout"],
		"PCHAR"  => ["in", "out", "inout"],
		"PBLOB"  => ["in", "out", "inout"],
	}.freeze

	@@allowed_convs = ["stdcall", "cdecl"]

	@@directions = ["in", "out", "inout", "return"].freeze

	attr_reader :return_type,  :params, :windows_name, :calling_conv

	def initialize(return_type, params, windows_name, calling_conv="stdcall")
		check_return_type(return_type) # we do error checking as early as possible so the library is easier to use
		check_params(params)
		check_calling_conv(calling_conv)
		@return_type = return_type
		@params = params
		@windows_name = windows_name
		@calling_conv = calling_conv
	end

	private

	def check_calling_conv(conv)
		if not @@allowed_convs.include?(conv)
			raise ArgumentError, "Calling convention unknown: #{conv}."
		end
	end

	def check_type_exists (type)
		if not @@allowed_datatypes.has_key?(type)
			raise ArgumentError, "Type unknown: #{type}. Allowed types: #{PP.pp(@@allowed_datatypes.keys, "")}"
		end
	end

	def check_return_type (type)
		check_type_exists(type)
		if not @@allowed_datatypes[type].include?("return")
			raise ArgumentError, "#{type} is not allowed as a return type"
		end
	end

	def check_params (params)
		params.each do |param|
			raise ArgumentError, "each param must be descriped by a three-tuple [type,name,direction]" unless param.length == 3
			type = param[0]
			direction = param[2]

			# Assert a valid type
			check_type_exists(type)

			# Only our set of predefined directions are valid
			unless @@directions.include?(direction)
				raise ArgumentError, "invalid direction: #{direction}"
			end

			# 'return' is not a valid direction in this context
			unless direction != "return"
				raise "direction 'return' is only for the return value of the function."
			end
		end
	end

end

end; end; end; end; end; end
