# -*- coding: binary -*-

require 'rex/post/process'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry_subsystem/registry_key'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry_subsystem/registry_value'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry_subsystem/remote_registry_key'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

###
#
# This class provides access to the Windows registry on the remote
# machine.
#
###
class Registry

  class << self
    attr_accessor :client
  end

  ##
  #
  # Registry key interaction
  #
  ##

  #
  # Opens the supplied registry key relative to the root key with
  # the supplied permissions.  Right now this is merely a wrapper around
  # create_key.
  #

  def Registry.load_key(root_key,base_key,hive_file)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_LOAD_KEY)
    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    request.add_tlv(TLV_TYPE_FILE_PATH, client.unicode_filter_decode( hive_file ))

    response = client.send_request(request)
    return response.get_tlv(TLV_TYPE_RESULT).value
  end

  def Registry.unload_key(root_key,base_key)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_UNLOAD_KEY)
    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    response = client.send_request(request)
    return response.get_tlv(TLV_TYPE_RESULT).value
  end


  def Registry.open_key(root_key, base_key, perm = KEY_READ)
    # If no base key was provided, just return the root_key.
    if (base_key == nil or base_key.length == 0)
      return RegistrySubsystem::RegistryKey.new(client, root_key, base_key, perm, root_key)
    end

    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_OPEN_KEY)

    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    request.add_tlv(TLV_TYPE_PERMISSION, perm)

    response = client.send_request(request)

    return Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryKey.new(
        client, root_key, base_key, perm, response.get_tlv(TLV_TYPE_HKEY).value)
  end

  # Checks if a key exists on the target registry
  #
  # @param root_key [String] the root part of the key path. Ex: HKEY_LOCAL_MACHINE
  # @param base_key [String] the base part of the key path
  # @return [Boolean] true if the key exists on the target registry, false otherwise, even
  #   it the session hasn't permissions to access the target key.
  # @raise [TimeoutError] if the timeout expires when waiting the answer
  # @raise [Rex::Post::Meterpreter::RequestError] if the parameters are not valid
  def Registry.check_key_exists(root_key, base_key)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_CHECK_KEY_EXISTS)
    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    response = client.send_request(request)
    return response.get_tlv(TLV_TYPE_BOOL).value
  end

  #
  # Opens the supplied registry key on the specified remote host. Requires that the
  # current process has credentials to access the target and that the target has the
  # remote registry service running.
  #
  def Registry.open_remote_key(target_host, root_key)

    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_OPEN_REMOTE_KEY)

    request.add_tlv(TLV_TYPE_TARGET_HOST, target_host)
    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)

    response = client.send_request(request)

    return Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RemoteRegistryKey.new(
        client, target_host, root_key, response.get_tlv(TLV_TYPE_HKEY).value)
  end

  #
  # Creates the supplied registry key or opens it if it already exists.
  #
  def Registry.create_key(root_key, base_key, perm = KEY_READ)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_CREATE_KEY)

    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    request.add_tlv(TLV_TYPE_PERMISSION, perm)

    response = client.send_request(request)

    return Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryKey.new(
        client, root_key, base_key, perm, response.get_tlv(TLV_TYPE_HKEY).value)
  end

  #
  # Deletes the supplied registry key.
  #
  def Registry.delete_key(root_key, base_key, recursive = true)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_DELETE_KEY)
    flags   = 0

    if (recursive)
      flags |= DELETE_KEY_FLAG_RECURSIVE
    end

    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    request.add_tlv(TLV_TYPE_FLAGS, flags)

    if (client.send_request(request) != nil)
      return true
    end

    return false
  end

  #
  # Closes the supplied registry key.
  #
  def Registry.close_key(hkey)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_CLOSE_KEY)

    request.add_tlv(TLV_TYPE_HKEY, hkey)

    client.send_packet(request)

    return true
  end

  #
  # Enumerates the supplied registry key returning an array of key names.
  #
  def Registry.enum_key(hkey)
    keys    = []
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_ENUM_KEY)

    request.add_tlv(TLV_TYPE_HKEY, hkey)

    response = client.send_request(request)

    # Enumerate through all of the registry keys
    response.each(TLV_TYPE_KEY_NAME) { |key_name|
      keys << key_name.value
    }

    return keys
  end

  def Registry.enum_key_direct(root_key, base_key, perm = KEY_READ)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_ENUM_KEY_DIRECT)
    keys    = []

    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    request.add_tlv(TLV_TYPE_PERMISSION, perm)

    response = client.send_request(request)

    # Enumerate through all of the registry keys
    response.each(TLV_TYPE_KEY_NAME) do |key_name|
      keys << key_name.value
    end

    keys
  end

  ##
  #
  # Registry value interaction
  #
  ##

  #
  # Sets the registry value relative to the supplied hkey.
  #
  def Registry.set_value(hkey, name, type, data)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_SET_VALUE)

    request.add_tlv(TLV_TYPE_HKEY, hkey)
    request.add_tlv(TLV_TYPE_VALUE_NAME, name)
    request.add_tlv(TLV_TYPE_VALUE_TYPE, type)
    request.add_tlv(TLV_TYPE_VALUE_DATA, self.ruby2reg_value(type, data))

    client.send_request(request)

    return true
  end

  def Registry.set_value_direct(root_key, base_key, name, type, data, perm = KEY_WRITE)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_SET_VALUE_DIRECT)

    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    request.add_tlv(TLV_TYPE_PERMISSION, perm)
    request.add_tlv(TLV_TYPE_VALUE_NAME, name)
    request.add_tlv(TLV_TYPE_VALUE_TYPE, type)
    request.add_tlv(TLV_TYPE_VALUE_DATA, self.ruby2reg_value(type, data))

    client.send_request(request)

    true
  end

  #
  # Queries the registry value supplied in name and returns an
  # initialized RegistryValue instance if a match is found.
  #
  def Registry.query_value_direct(root_key, base_key, name, perm = KEY_READ)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_QUERY_VALUE_DIRECT)

    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    request.add_tlv(TLV_TYPE_PERMISSION, perm)
    request.add_tlv(TLV_TYPE_VALUE_NAME, name)

    response = client.send_request(request)

    type = response.get_tlv(TLV_TYPE_VALUE_TYPE).value
    data = self.reg2ruby_value(type, response.get_tlv(TLV_TYPE_VALUE_DATA).value)

    Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryValue.new(
        client, 0, name, type, data)
  end

  def Registry.query_value(hkey, name)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_QUERY_VALUE)

    request.add_tlv(TLV_TYPE_HKEY, hkey)
    request.add_tlv(TLV_TYPE_VALUE_NAME, name)

    response = client.send_request(request)

    type = response.get_tlv(TLV_TYPE_VALUE_TYPE).value
    data = self.reg2ruby_value(type, response.get_tlv(TLV_TYPE_VALUE_DATA).value)


    return Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryValue.new(
        client, hkey, name, type, data)
  end

  #
  # Deletes the registry value supplied in name from the supplied
  # registry key.
  #
  def Registry.delete_value(hkey, name)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_DELETE_VALUE)

    request.add_tlv(TLV_TYPE_HKEY, hkey)
    request.add_tlv(TLV_TYPE_VALUE_NAME, name)

    if (client.send_request(request) != nil)
      return true
    end

    return false
  end

  #
  # Queries the registry class name and returns a string
  #
  def Registry.query_class(hkey)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_QUERY_CLASS)

    request.add_tlv(TLV_TYPE_HKEY, hkey)

    response = client.send_request(request)
    cls = response.get_tlv(TLV_TYPE_VALUE_DATA)
    return nil if not cls
    data = cls.value.gsub(/\x00.*/n, '')
    return data
  end

  #
  # Enumerates all of the values at the supplied hkey including their
  # names.  An array of RegistryValue's is returned.
  #
  def Registry.enum_value(hkey)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_ENUM_VALUE)
    values  = []

    request.add_tlv(TLV_TYPE_HKEY, hkey)

    response = client.send_request(request)

    response.each(TLV_TYPE_VALUE_NAME) { |value_name|
      values << Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryValue.new(
          client, hkey, value_name.value)
    }

    return values
  end

  def Registry.enum_value_direct(root_key, base_key, perm = KEY_READ)
    request = Packet.create_request(COMMAND_ID_STDAPI_REGISTRY_ENUM_VALUE_DIRECT)
    values  = []

    request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
    request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
    request.add_tlv(TLV_TYPE_PERMISSION, perm)

    response = client.send_request(request)

    response.each(TLV_TYPE_VALUE_NAME) do |value_name|
      values << Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryValue.new(
          client, 0, value_name.value)
    end

    values
  end

  #
  # Return the key value associated with the supplied string.  This is useful
  # for converting HKLM as a string into its actual integer representation.
  #
  def self.key2str(key)
    if (key == 'HKLM' or key == 'HKEY_LOCAL_MACHINE')
      return HKEY_LOCAL_MACHINE
    elsif (key == 'HKCU' or key == 'HKEY_CURRENT_USER')
      return HKEY_CURRENT_USER
    elsif (key == 'HKU' or key == 'HKEY_USERS')
      return HKEY_USERS
    elsif (key == 'HKCR' or key == 'HKEY_CLASSES_ROOT')
      return HKEY_CLASSES_ROOT
    elsif (key == 'HKEY_CURRENT_CONFIG')
      return HKEY_CURRENT_CONFIG
    elsif (key == 'HKEY_PERFORMANCE_DATA')
      return HKEY_PERFORMANCE_DATA
    elsif (key == 'HKEY_DYN_DATA')
      return HKEY_DYN_DATA
    else
      raise ArgumentError, "Unknown key: #{key}"
    end
  end

  #
  # Returns the integer value associated with the supplied registry value
  # type (like REG_SZ).
  #
  # @see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724884(v=vs.85).aspx
  # @param type [String] A Windows registry type constant name, e.g. 'REG_SZ'
  # @return [Integer] one of the `REG_*` constants
  def self.type2str(type)
    case type
    when 'REG_BINARY'    then REG_BINARY
    when 'REG_DWORD'     then REG_DWORD
    when 'REG_EXPAND_SZ' then REG_EXPAND_SZ
    when 'REG_MULTI_SZ'  then REG_MULTI_SZ
    when 'REG_NONE'      then REG_NONE
    when 'REG_QWORD'     then REG_QWORD
    when 'REG_SZ'        then REG_SZ
    else
      nil
    end
  end

  #
  # Split the supplied full registry key into its root key and base key.  For
  # instance, passing HKLM\Software\Dog will return [ HKEY_LOCAL_MACHINE,
  # 'Software\Dog' ]
  #
  def self.splitkey(str)
    if (str =~ /^(.+?)[\\]{1,}(.*)$/)
      [ key2str($1), $2 ]
    else
      [ key2str(str), nil ]
    end
  end

  class << self
    private

    def ruby2reg_value(type, value)
      case type
      when REG_DWORD
        value = [value.to_i].pack('L<')
      when REG_EXPAND_SZ
        value += "\x00".b
      when REG_MULTI_SZ
        value = value.join("\x00".b) + "\x00\x00".b
      when REG_QWORD
        value = [value.to_i].pack('Q<')
      when REG_SZ
        value += "\x00".b
      end

      value
    end

    def reg2ruby_value(type, value)
      case type
      when REG_DWORD
        value = value.unpack1('L>')
      when REG_EXPAND_SZ
        value = value[0..-2]
      when REG_MULTI_SZ
        value = value[0..-3].split("\x00".b)
      when REG_QWORD
        value = value.unpack1('Q<')
      when REG_SZ
        value = value[0..-2]
      end

      value
    end
  end

end

end; end; end; end; end; end

