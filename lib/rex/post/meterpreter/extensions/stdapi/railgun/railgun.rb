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

#
# zeroSteiner - April 2017 - added support for non-windows platforms
#

require 'pp'
require 'enumerator'

require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'
require 'rex/post/meterpreter/extensions/stdapi/railgun/util'
require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'
require 'rex/post/meterpreter/extensions/stdapi/railgun/multicall'
require 'rex/post/meterpreter/extensions/stdapi/railgun/library'
require 'rex/post/meterpreter/extensions/stdapi/railgun/library_wrapper'

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
  # Railgun::Library's that have builtin definitions.
  #
  # If you want to add additional library definitions to be preloaded create a
  # definition class 'rex/post/meterpreter/extensions/stdapi/railgun/def/$platform/'.
  # Naming is important and should follow convention.  For example, if your
  # library's name was "my_library"
  # file name:    def_my_library.rb
  # class name:   Def_my_library
  # entry below: 'my_library'
  #
  BUILTIN_LIBRARIES = {
    'linux' => [
      'libc'
    ].freeze,
    'osx' => [
      'libc',
      'libobjc'
    ].freeze,
    'windows' => [
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
      'version',
      'psapi'
    ].freeze
  }.freeze

  ##
  # Returns a Hash containing libraries added to this instance with #add_library
  # as well as references to any frozen cached libraries added directly in
  # #get_library and copies of any frozen libraries (added directly with
  # #add_function) that the user attempted to modify with #add_function.
  #
  # Keys are friendly library names and values are the corresponding library instance
  attr_accessor :libraries

  ##
  # Contains a reference to the client that corresponds to this instance of railgun
  attr_accessor :client

  ##
  # These libraries are loaded lazily and then shared amongst all railgun
  # instances. For safety reasons this variable should only be read/written
  # within #get_library.
  @@cached_libraries = {}

  # if you are going to touch @@cached_libraries, wear protection
  @@cache_semaphore = Mutex.new

  def initialize(client)
    self.client = client
    self.libraries = {}
  end

  def self.builtin_libraries
    BUILTIN_LIBRARIES[client.platform]
  end

  #
  # Return this Railgun's Util instance.
  #
  def util
    if @util.nil?
      @util = Util.new(self, client.arch)
    end

    return @util
  end

  #
  # Return this Railgun's platform specific ApiConstants class.
  #
  def api_constants
    if @api_constants.nil?
      require "rex/post/meterpreter/extensions/stdapi/railgun/def/#{client.platform}/api_constants"
      @api_constants = Def.const_get('DefApiConstants_' << client.platform)
    end

    return @api_constants
  end

  #
  # Return this Railgun's ConstManager instance, initially populated with
  # constants defined in ApiConstants.
  #
  def constant_manager
    # Loads lazily
    return api_constants.manager
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
  def memwrite(address, data, length=nil)

    length = data.length if length.nil?
    raise "Invalid parameters." if(not address or not data or not length)

    request = Packet.create_request('stdapi_railgun_memwrite')
    request.add_tlv(TLV_TYPE_RAILGUN_MEM_ADDRESS, address)
    request.add_tlv(TLV_TYPE_RAILGUN_MEM_DATA, data)
    request.add_tlv(TLV_TYPE_RAILGUN_MEM_LENGTH, length)

    response = client.send_request(request)
    return response.result == 0
  end

  #
  # Adds a function to an existing library definition.
  #
  # If the library definition is frozen (ideally this should be the case for all
  # cached libraries) an unfrozen copy is created and used henceforth for this
  # instance.
  #
  def add_function(lib_name, function_name, return_type, params, remote_name=nil, calling_conv='stdcall')
    unless known_library_names.include?(lib_name)
      raise "Library #{lib_name} not found. Known libraries: #{PP.pp(known_library_names, '')}"
    end

    lib = get_library(lib_name)

    # For backwards compatibility, we ensure the library is thawed
    if lib.frozen?
      # Duplicate not only the library, but its functions as well, frozen status will be lost
      lib = Marshal.load(Marshal.dump(lib))

      # Update local libraries with the modifiable duplicate
      libraries[lib_name] = lib
    end

    lib.add_function(function_name, return_type, params, remote_name, calling_conv)
  end

  #
  # Adds a library to this Railgun.
  #
  # The +remote_name+ is the name used on the remote system and should be
  # set appropriately if you want to include a path or the library name contains
  # non-ruby-approved characters.
  #
  # Raises an exception if a library with the given name has already been
  # defined.
  #
  def add_library(lib_name, remote_name=lib_name)
    if libraries.has_key? lib_name
      raise "A library of name #{lib_name} has already been loaded."
    end

    libraries[lib_name] = Library.new(remote_name, constant_manager)
  end
  alias_method :add_dll, :add_library

  def known_library_names
    return BUILTIN_LIBRARIES[client.platform] | libraries.keys
  end

  #
  # Attempts to provide a library instance of the given name. Handles lazy
  # loading and caching. Note that if a library of the given name does not exist
  # then nil is returned.
  #
  def get_library(lib_name)
    # If the library is not local, we now either load it from cache or load it
    # lazily. In either case, a reference to the library is stored in the
    # collection "libraries". If the library can not be found/created, no
    # actions are taken.
    unless libraries.has_key? lib_name
      # use a platform-specific name for caching to avoid conflicts with
      # libraries that exist on multiple platforms, e.g. libc.
      cached_lib_name = "#{client.platform}.#{lib_name}"
      # We read and write to @@cached_libraries and rely on state consistency
      @@cache_semaphore.synchronize do
        if @@cached_libraries.has_key? cached_lib_name
          libraries[lib_name] = @@cached_libraries[cached_lib_name]
        elsif BUILTIN_LIBRARIES[client.platform].include? lib_name
          # I highly doubt this case will ever occur, but I am paranoid
          if lib_name !~ /^\w+$/
            raise "Library name #{lib_name} is bad. Correct Railgun::BUILTIN_LIBRARIES['#{client.platform}']"
          end

          require "rex/post/meterpreter/extensions/stdapi/railgun/def/#{client.platform}/def_#{lib_name}"
          lib = Def.const_get("Def_#{client.platform}_#{lib_name}").create_library(constant_manager).freeze

          @@cached_libraries[cached_lib_name] = lib
          libraries[lib_name] = lib
        end
      end

    end

    return libraries[lib_name]
  end
  alias_method :get_dll, :get_library

  #
  # Fake having members like user32 and kernel32.
  # reason is that
  #   ...user32.MessageBoxW()
  # is prettier than
  #   ...libraries["user32"].functions["MessageBoxW"]()
  #
  def method_missing(lib_symbol, *args)
    lib_name = lib_symbol.to_s

    unless known_library_names.include? lib_name
      raise "Library #{lib_name} not found. Known libraries: #{PP.pp(known_library_names, '')}"
    end

    lib = get_library(lib_name)

    return LibraryWrapper.new(lib, client)
  end

  #
  # Return a constant matching +str+.
  #
  def const(str)
    return constant_manager.parse(str)
  end

  #
  # The multi-call shorthand (["kernel32", "ExitProcess", [0]])
  #
  def multi(functions)
    if @multicaller.nil?
      @multicaller = MultiCaller.new(client, self, constant_manager)
    end

    return @multicaller.call(functions)
  end
end

end; end; end; end; end; end
