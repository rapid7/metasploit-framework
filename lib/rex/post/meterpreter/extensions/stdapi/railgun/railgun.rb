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

#
# sf - Sept 2010 - Modified for x64 support and merged into the stdapi extension.
#

require 'pp'
require 'enumerator'
require 'rex/post/meterpreter/extensions/stdapi/railgun/api_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'
require 'rex/post/meterpreter/extensions/stdapi/railgun/model'
require 'rex/post/meterpreter/extensions/stdapi/railgun/multicall'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

#
# The Railgun class to dynamically expose the Windows API.
#
class Railgun

	def initialize( client )

		@client = client
		@dll    = ::Hash.new
		
		@win_consts = WinConstManager.new()
		
		@constants_loaded = false

		# Load the multi-caller
		@multicaller = MultiCaller.new( @client, self, @win_consts )
	end
	
	# read data from a memory address on the host (useful for working with LPVOID parameters)
	def memread( address, length )
	
		raise "Invalid parameters." if( not address or not length )
		
		request = Packet.create_request( 'stdapi_railgun_memread' )
		
		request.add_tlv( TLV_TYPE_RAILGUN_MEM_ADDRESS, address )
		request.add_tlv( TLV_TYPE_RAILGUN_MEM_LENGTH, length )

		response = client.send_request( request )
		if( response.result == 0 )
			return response.get_tlv_value( TLV_TYPE_RAILGUN_MEM_DATA )
		end
		
		return nil
	end
	
	# write data to a memory address on the host (useful for working with LPVOID parameters)
	def memwrite( address, data, length )
	
		raise "Invalid parameters." if( not address or not data or not length )
		
		request = Packet.create_request( 'stdapi_railgun_memwrite' )
		
		request.add_tlv( TLV_TYPE_RAILGUN_MEM_ADDRESS, address )
		request.add_tlv( TLV_TYPE_RAILGUN_MEM_DATA, data )
		request.add_tlv( TLV_TYPE_RAILGUN_MEM_LENGTH, length )

		response = client.send_request( request )
		if( response.result == 0 )
			return true
		end
		
		return false
	end
	
	# adds a function to an existing DLL-definition
	def add_function(dll_name, function_name, return_type, params, windows_name=nil)
		raise "DLL #{dll_name} not found. Known DLLs: #{PP.pp(@dll.keys, "")}" unless @dll.has_key? dll_name
		@dll[dll_name].add_function(function_name, return_type, params, windows_name)
	end

	# adds a function to an existing DLL-definition
	# you can override the dll name if you want to include a path or the DLL name contains
	# non-ruby-approved characters
	def add_dll(dll_name, windows_name=nil)
		raise "DLL #{dll_name} already exists. Existing DLLs: #{PP.pp(@dll.keys, "")}" unless not @dll.has_key? dll_name
		if( windows_name == nil )
			windows_name = dll_name
		end
		@dll[dll_name] = DLL.new(windows_name, @client, @win_consts)
	end

	def get_dll( dll_name )
		# sf: we now lazy load the module definitions as needed to avoid the performance hit
		#     to stdapi if we do it upon initilization (the user may never use railgun or else
		#     require only a portion of the modules exposed by railgun so no need to pre load them)
		if( not @dll.has_key?( dll_name ) )
		
			# the constants are also lazy loaded the first time we call const() or any API function...
			if( not @constants_loaded )
				ApiConstants.add_constants( @win_consts )
				@constants_loaded = true
			end

			case dll_name
				when 'kernel32'
					require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_kernel32'
					Def::Def_kernel32.add_imports(self)
				when 'ntdll'
					require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_ntdll'
					Def::Def_ntdll.add_imports(self)
				when 'user32'
					require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_user32'
					Def::Def_user32.add_imports(self)
				when 'ws2_32'
					require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_ws2_32'
					Def::Def_ws2_32.add_imports(self)
				when 'iphlpapi'
					require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_iphlpapi'
					Def::Def_iphlpapi.add_imports(self)
				when 'advapi32'
					require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_advapi32'
					Def::Def_advapi32.add_imports(self)
				when 'shell32'
					require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_shell32'
					Def::Def_shell32.add_imports(self)
			end
			
			if( @dll.has_key?( dll_name ) )
				return @dll[dll_name]
			end
			
		else
			return @dll[dll_name]
		end
		
		return nil
	end
	
	# we fake having members like user32 and kernel32.
	# reason is that
	#   ...user32.MessageBoxW()
	# is prettier than
	#   ...dlls["user32"].functions["MessageBoxW"]()
	def method_missing(dll_symbol, *args)
		dll_name = dll_symbol.to_s

		self.get_dll( dll_name )
		
		raise "DLL #{dll_name} not found. Known DLLs: #{PP.pp(@dll.keys, "")}" unless @dll.has_key? dll_name
		
		return @dll[dll_name]
	end

	# Give the programmer access to constants
	def const(str)
		# the constants are also lazy loaded the first time we call const() or any API function...
		if( not @constants_loaded )
			ApiConstants.add_constants( @win_consts )
			@constants_loaded = true
		end
		return @win_consts.parse(str)
	end

	# The multi-call shorthand ( ["kernel32", "ExitProcess", [0]] )
	def multi(functions)
		@multicaller.call(functions)
	end

	attr_accessor :client, :dll, :multicaller, :win_consts
	
end

end; end; end; end; end; end