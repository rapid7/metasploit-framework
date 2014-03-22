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

#
# sf - Sept 2010 - Modified for x64 support and merged into the stdapi extension.
#

#
# chao - June 2011 - major overhaul of dll lazy loading, caching, and bit of everything
#

require 'pp'
require 'enumerator'

require 'rex/post/meterpreter/extensions/stdapi/railgun/api_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'
require 'rex/post/meterpreter/extensions/stdapi/railgun/util'
require 'rex/post/meterpreter/extensions/stdapi/railgun/win_const_manager'
require 'rex/post/meterpreter/extensions/stdapi/railgun/multicall'
require 'rex/post/meterpreter/extensions/stdapi/railgun/dll'
require 'rex/post/meterpreter/extensions/stdapi/railgun/dll_wrapper'

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

  #
  # Railgun::DLL's that have builtin definitions.
  #
  # If you want to add additional DLL definitions to be preloaded create a
  # definition class 'rex/post/meterpreter/extensions/stdapi/railgun/def/'.
  # Naming is important and should follow convention.  For example, if your
  # dll's name was "my_dll"
  # file name:    def_my_dll.rb
  # class name:   Def_my_dll
  # entry below: 'my_dll'
  #
  BUILTIN_DLLS = [
    'kernel32',
    'ntdll',
    'user32',
    'ws2_32',
    'iphlpapi',
    'advapi32',
    'shell32',
    'netapi32',
    'crypt32',
    'wlanapi',
    'wldap32',
    'version'
  ].freeze

  ##
  # Returns a Hash containing DLLs added to this instance with #add_dll
  # as well as references to any frozen cached dlls added directly in #get_dll
  # and copies of any frozen dlls (added directly with #add_function)
  # that the user attempted to modify with #add_function.
  #
  # Keys are friendly DLL names and values are the corresponding DLL instance
  attr_accessor :dlls

  ##
  # Contains a reference to the client that corresponds to this instance of railgun
  attr_accessor :client

  ##
  # These DLLs are loaded lazily and then shared amongst all railgun instances.
  # For safety reasons this variable should only be read/written within #get_dll.
  @@cached_dlls = {}

  # if you are going to touch @@cached_dlls, wear protection
  @@cache_semaphore = Mutex.new

  def initialize(client)
    self.client = client
    self.dlls = {}
  end

  def self.builtin_dlls
    BUILTIN_DLLS
  end

  #
  # Return this Railgun's Util instance.
  #
  def util
    if @util.nil?
      @util = Util.new(self, client.platform)
    end

    return @util
  end

  #
  # Return this Railgun's WinConstManager instance, initially populated with
  # constants defined in ApiConstants.
  #
  def constant_manager
    # Loads lazily
    return ApiConstants.manager
  end

  #
  # Read data from a memory address on the host (useful for working with
  # LPVOID parameters)
  #
  def memread(address, length)

    raise "Invalid parameters." if(not address or not length)

    request = Packet.create_request('stdapi_railgun_memread')

    request.add_tlv(TLV_TYPE_RAILGUN_MEM_ADDRESS, address)
    request.add_tlv(TLV_TYPE_RAILGUN_MEM_LENGTH, length)

    response = client.send_request(request)
    if(response.result == 0)
      return response.get_tlv_value(TLV_TYPE_RAILGUN_MEM_DATA)
    end

    return nil
  end

  #
  # Write data to a memory address on the host (useful for working with
  # LPVOID parameters)
  #
  def memwrite(address, data, length)

    raise "Invalid parameters." if(not address or not data or not length)

    request = Packet.create_request('stdapi_railgun_memwrite')

    request.add_tlv(TLV_TYPE_RAILGUN_MEM_ADDRESS, address)
    request.add_tlv(TLV_TYPE_RAILGUN_MEM_DATA, data)
    request.add_tlv(TLV_TYPE_RAILGUN_MEM_LENGTH, length)

    response = client.send_request(request)
    if(response.result == 0)
      return true
    end

    return false
  end

  #
  # Adds a function to an existing DLL definition.
  #
  # If the DLL definition is frozen (ideally this should be the case for all
  # cached dlls) an unfrozen copy is created and used henceforth for this
  # instance.
  #
  def add_function(dll_name, function_name, return_type, params, windows_name=nil, calling_conv="stdcall")

    unless known_dll_names.include?(dll_name)
      raise "DLL #{dll_name} not found. Known DLLs: #{PP.pp(known_dll_names, "")}"
    end

    dll = get_dll(dll_name)

    # For backwards compatibility, we ensure the dll is thawed
    if dll.frozen?
      # Duplicate not only the dll, but its functions as well. Frozen status will be lost
      dll = Marshal.load(Marshal.dump(dll))

      # Update local dlls with the modifiable duplicate
      dlls[dll_name] = dll
    end

    dll.add_function(function_name, return_type, params, windows_name, calling_conv)
  end

  #
  # Adds a DLL to this Railgun.
  #
  # The +windows_name+ is the name used on the remote system and should be
  # set appropriately if you want to include a path or the DLL name contains
  # non-ruby-approved characters.
  #
  # Raises an exception if a dll with the given name has already been
  # defined.
  #
  def add_dll(dll_name, windows_name=dll_name)

    if dlls.has_key? dll_name
      raise "A DLL of name #{dll_name} has already been loaded."
    end

    dlls[dll_name] = DLL.new(windows_name, constant_manager)
  end


  def known_dll_names
    return BUILTIN_DLLS | dlls.keys
  end

  #
  # Attempts to provide a DLL instance of the given name. Handles lazy
  # loading and caching.  Note that if a DLL of the given name does not
  # exist, returns nil
  #
  def get_dll(dll_name)

    # If the DLL is not local, we now either load it from cache or load it lazily.
    # In either case, a reference to the dll is stored in the collection "dlls"
    # If the DLL can not be found/created, no actions are taken
    unless dlls.has_key? dll_name
      # We read and write to @@cached_dlls and rely on state consistency
      @@cache_semaphore.synchronize do
        if @@cached_dlls.has_key? dll_name
          dlls[dll_name] = @@cached_dlls[dll_name]
        elsif BUILTIN_DLLS.include? dll_name
          # I highly doubt this case will ever occur, but I am paranoid
          if dll_name !~ /^\w+$/
            raise "DLL name #{dll_name} is bad. Correct Railgun::BUILTIN_DLLS"
          end

          require 'rex/post/meterpreter/extensions/stdapi/railgun/def/def_' << dll_name
          dll = Def.const_get('Def_' << dll_name).create_dll.freeze

          @@cached_dlls[dll_name] = dll
          dlls[dll_name] = dll
        end
      end

    end

    return dlls[dll_name]
  end

  #
  # Fake having members like user32 and kernel32.
  # reason is that
  #   ...user32.MessageBoxW()
  # is prettier than
  #   ...dlls["user32"].functions["MessageBoxW"]()
  #
  def method_missing(dll_symbol, *args)
    dll_name = dll_symbol.to_s

    unless known_dll_names.include? dll_name
      raise "DLL #{dll_name} not found. Known DLLs: #{PP.pp(known_dll_names, '')}"
    end

    dll = get_dll(dll_name)

    return DLLWrapper.new(dll, client)
  end

  #
  # Return a Windows constant matching +str+.
  #
  def const(str)
    return constant_manager.parse(str)
  end

  #
  # The multi-call shorthand (["kernel32", "ExitProcess", [0]])
  #
  def multi(functions)
    if @multicaller.nil?
      @multicaller = MultiCaller.new(client, self, ApiConstants.manager)
    end

    return @multicaller.call(functions)
  end
end

end; end; end; end; end; end
