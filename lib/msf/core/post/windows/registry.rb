# -*- coding: binary -*-

require 'msf/core/post/windows/cli_parse'

module Msf
class Post
module Windows

module Registry

  include Msf::Post::Windows::CliParse

  #
  # This is the default view. It reflects what the remote process would see
  # natively. So, if you are using a remote 32-bit meterpreter session, you
  # will see 32-bit registry keys and values.
  #
  REGISTRY_VIEW_NATIVE = 0

  #
  # Access 32-bit registry keys and values regardless of whether the session is
  # 32 or 64-bit.
  #
  REGISTRY_VIEW_32_BIT = 1

  #
  # Access 64-bit registry keys and values regardless of whether the session is
  # 32 or 64-bit.
  #
  REGISTRY_VIEW_64_BIT = 2

  #
  # Windows Registry Constants.
  #
  REG_NONE = 1
  REG_SZ = 1
  REG_EXPAND_SZ = 2
  REG_BINARY = 3
  REG_DWORD = 4
  REG_LITTLE_ENDIAN = 4
  REG_BIG_ENDIAN = 5
  REG_LINK = 6
  REG_MULTI_SZ = 7

  HKEY_CLASSES_ROOT = 0x80000000
  HKEY_CURRENT_USER = 0x80000001
  HKEY_LOCAL_MACHINE = 0x80000002
  HKEY_USERS = 0x80000003
  HKEY_PERFORMANCE_DATA = 0x80000004
  HKEY_CURRENT_CONFIG = 0x80000005
  HKEY_DYN_DATA = 0x80000006

  #
  # Lookup registry hives by key.
  #
  def registry_hive_lookup(hive)
    case hive
    when 'HKCR'
      HKEY_LOCAL_MACHINE
    when 'HKCU'
      HKEY_CURRENT_USER
    when 'HKLM'
      HKEY_LOCAL_MACHINE
    when 'HKU'
      HKEY_USERS
    when 'HKPD'
      HKEY_PERFORMANCE_DATA
    when 'HKCC'
      HKEY_CURRENT_CONFIG
    when 'HKDD'
      HKEY_DYN_DATA
    else
      HKEY_LOCAL_MACHINE
    end
  end

  #
  # Load a hive file
  #
  def registry_loadkey(key, file)
    if session_has_registry_ext
      meterpreter_registry_loadkey(key, file)
    else
      shell_registry_loadkey(key, file)
    end
  end

  #
  # Unload a hive file
  #
  def registry_unloadkey(key)
    if session_has_registry_ext
      meterpreter_registry_unloadkey(key)
    else
      shell_registry_unloadkey(key)
    end
  end

  #
  # Create the given registry key
  #
  def registry_createkey(key, view = REGISTRY_VIEW_NATIVE)
    if session_has_registry_ext
      meterpreter_registry_createkey(key, view)
    else
      shell_registry_createkey(key, view)
    end
  end

  #
  # Deletes a registry value given the key and value name
  #
  # returns true if succesful
  #
  def registry_deleteval(key, valname, view = REGISTRY_VIEW_NATIVE)
    if session_has_registry_ext
      meterpreter_registry_deleteval(key, valname, view)
    else
      shell_registry_deleteval(key, valname, view)
    end
  end

  #
  # Delete a given registry key
  #
  # returns true if succesful
  #
  def registry_deletekey(key, view = REGISTRY_VIEW_NATIVE)
    if session_has_registry_ext
      meterpreter_registry_deletekey(key, view)
    else
      shell_registry_deletekey(key, view)
    end
  end

  #
  # Return an array of subkeys for the given registry key
  #
  def registry_enumkeys(key, view = REGISTRY_VIEW_NATIVE)
    if session_has_registry_ext
      meterpreter_registry_enumkeys(key, view)
    else
      shell_registry_enumkeys(key, view)
    end
  end

  #
  # Return an array of value names for the given registry key
  #
  def registry_enumvals(key, view = REGISTRY_VIEW_NATIVE)
    if session_has_registry_ext
      meterpreter_registry_enumvals(key, view)
    else
      shell_registry_enumvals(key, view)
    end
  end

  #
  # Return the data of a given registry key and value
  #
  def registry_getvaldata(key, valname, view = REGISTRY_VIEW_NATIVE)
    if session_has_registry_ext
      meterpreter_registry_getvaldata(key, valname, view)
    else
      shell_registry_getvaldata(key, valname, view)
    end
  end

  #
  # Return the data and type of a given registry key and value
  #
  def registry_getvalinfo(key, valname, view = REGISTRY_VIEW_NATIVE)
    if session_has_registry_ext
      meterpreter_registry_getvalinfo(key, valname, view)
    else
      shell_registry_getvalinfo(key, valname, view)
    end
  end

  #
  # Sets the data for a given value and type of data on the target registry
  #
  # returns true if succesful
  #
  def registry_setvaldata(key, valname, data, type, view = REGISTRY_VIEW_NATIVE)
    if session_has_registry_ext
      meterpreter_registry_setvaldata(key, valname, data, type, view)
    else
      shell_registry_setvaldata(key, valname, data, type, view)
    end
  end

  # Checks if a key exists on the target registry
  #
  # @param key [String] the full path of the key to check
  # @return [Boolean] true if the key exists on the target registry, false otherwise
  #   (also in case of error)
  def registry_key_exist?(key)
    if session_has_registry_ext
      meterpreter_registry_key_exist?(key)
    else
      shell_registry_key_exist?(key)
    end
  end

protected

  #
  # Determines whether the session can use meterpreter registry methods
  #
  def session_has_registry_ext
    begin
      return !!(session.sys and session.sys.registry)
    rescue NoMethodError
      return false
    end
  end


  ##
  # Generic registry manipulation methods based on reg.exe
  ##

  def shell_registry_cmd(suffix, view = REGISTRY_VIEW_NATIVE)
    cmd = "cmd.exe /c reg"
    if view == REGISTRY_VIEW_32_BIT
      cmd += " /reg:32"
    elsif view == REGISTRY_VIEW_64_BIT
      cmd += " /reg:64"
    end
    cmd_exec("#{cmd} #{suffix}")
  end

  def shell_registry_cmd_result(suffix, view = REGISTRY_VIEW_NATIVE)
    results = shell_registry_cmd(suffix, view);
    results.include?('The operation completed successfully')
  end

  #
  # Use reg.exe to load the hive file +file+ into +key+
  #
  def shell_registry_loadkey(key, file)
    key = normalize_key(key)
    shell_registry_cmd_result("load \"#{key}\" \"#{file}\"")
  end

  #
  # Use reg.exe to unload the hive in +key+
  #
  def shell_registry_unloadkey(key)
    key = normalize_key(key)
    shell_registry_cmd_result("unload \"#{key}\"")
  end

  #
  # Use reg.exe to create a new registry key
  #
  def shell_registry_createkey(key, view)
    key = normalize_key(key)
    # REG ADD KeyName [/v ValueName | /ve] [/t Type] [/s Separator] [/d Data] [/f]
    shell_registry_cmd_result("add /f \"#{key}\"", view)
  end

  #
  # Use reg.exe to delete +valname+ in +key+
  #
  def shell_registry_deleteval(key, valname, view)
    key = normalize_key(key)
    # REG DELETE KeyName [/v ValueName | /ve | /va] [/f]
    shell_registry_cmd_result("delete \"#{key}\" /v \"#{valname}\" /f", view)
  end

  #
  # Use reg.exe to delete +key+ and all its subkeys and values
  #
  def shell_registry_deletekey(key, view)
    key = normalize_key(key)
    # REG DELETE KeyName [/v ValueName | /ve | /va] [/f]
    shell_registry_cmd_result("delete \"#{key}\" /f", view)
  end

  #
  # Use reg.exe to enumerate all the subkeys in +key+
  #
  def shell_registry_enumkeys(key, view)
    key = normalize_key(key)
    subkeys = []
    reg_data_types = 'REG_SZ|REG_MULTI_SZ|REG_DWORD_BIG_ENDIAN|REG_DWORD|REG_BINARY|'
    reg_data_types << 'REG_DWORD_LITTLE_ENDIAN|REG_NONE|REG_EXPAND_SZ|REG_LINK|REG_FULL_RESOURCE_DESCRIPTOR'
    bslashes = key.count('\\')
    results = shell_registry_cmd("query \"#{key}\"", view)
    unless results.include?('Error')
      results.each_line do |line|
        # now let's keep the ones that have a count = bslashes+1
        # feels like there's a smarter way to do this but...
        if (line.count('\\') == bslashes+1 && !line.ends_with?('\\'))
          #then it's a first level subkey
          subkeys << line.split('\\').last.chomp # take & chomp the last item only
        end
      end
    end
    subkeys
  end

  #
  # Use reg.exe to enumerate all the values in +key+
  #
  def shell_registry_enumvals(key, view)
    key = normalize_key(key)
    values = []
    reg_data_types = 'REG_SZ|REG_MULTI_SZ|REG_DWORD_BIG_ENDIAN|REG_DWORD|REG_BINARY|'
    reg_data_types << 'REG_DWORD_LITTLE_ENDIAN|REG_NONE|REG_EXPAND_SZ|REG_LINK|REG_FULL_RESOURCE_DESCRIPTOR'
    # REG QUERY KeyName [/v ValueName | /ve] [/s]
    results = shell_registry_cmd("query \"#{key}\"", view)
    unless results.include?('Error')
      if values = results.scan(/^ +.*[#{reg_data_types}].*/)
        # yanked the lines with legit REG value types like REG_SZ
        # now let's parse out the names (first field basically)
        values.collect! do |line|
          t = line.split(' ')[0].chomp #chomp for good measure
          # check if reg returned "<NO NAME>", which splits to "<NO", if so nil instead
          t = nil if t == "<NO"
          t
        end
      end
    end
    values
  end

  #
  # Returns the data portion of the value +valname+
  #
  def shell_registry_getvaldata(key, valname, view)
    a = shell_registry_getvalinfo(key, valname, view)
    a["Data"] || nil
  end

  #
  # Enumerate the type and data stored in the registry value +valname+ in
  # +key+
  #
  def shell_registry_getvalinfo(key, valname, view)
    key = normalize_key(key)
    value = {}
    value["Data"] = nil # defaults
    value["Type"] = nil
    # REG QUERY KeyName [/v ValueName | /ve] [/s]
    results = shell_registry_cmd("query \"#{key}\" /v \"#{valname}\"", view)
    if match_arr = /^ +#{valname}.*/i.match(results)
      # pull out the interesting line (the one with the value name in it)
      # and split it with ' ' yielding [valname,REGvaltype,REGdata]
      split_arr = match_arr[0].split(' ')
      value["Type"] = split_arr[1]
      value["Data"] = split_arr[2]
      # need to test to ensure all results can be parsed this way
    end
    value
  end

  #
  # Use reg.exe to add a value +valname+ in the key +key+ with the specified
  # +type+ and +data+
  #
  def shell_registry_setvaldata(key, valname, data, type, view)
    key = normalize_key(key)
    # REG ADD KeyName [/v ValueName | /ve] [/t Type] [/s Separator] [/d Data] [/f]
    # /f to overwrite w/o prompt
    shell_registry_cmd_result("add /f \"#{key}\" /v \"#{valname}\" /t \"#{type}\" /d \"#{data}\" /f", view)
  end

  # Checks if a key exists on the target registry using a shell session
  #
  # @param key [String] the full path of the key to check
  # @return [Boolean] true if the key exists on the target registry, false otherwise,
  #   even if case of error (invalid arguments) or the session hasn't permission to
  #   access the key
  def shell_registry_key_exist?(key)
    begin
      key = normalize_key(key)
    rescue ArgumentError
      return false
    end

    results = shell_registry_cmd("query \"#{key}\"")
    if results =~ /ERROR: /i
      return false
    else
      return true
    end
  end

  ##
  # Meterpreter-specific registry manipulation methods
  ##

  def meterpreter_registry_perms(perms, view = REGISTRY_VIEW_NATIVE)
    if view == REGISTRY_VIEW_32_BIT
      perms |= KEY_WOW64_32KEY
    elsif view == REGISTRY_VIEW_64_BIT
      perms |= KEY_WOW64_64KEY
    end
    perms
  end

  #
  # Load a registry hive stored in +file+ into +key+
  #
  def meterpreter_registry_loadkey(key, file)
    begin
      client.sys.config.getprivs()
      root_key, base_key = session.sys.registry.splitkey(key)
      begin
        loadres = session.sys.registry.load_key(root_key, base_key, file)
      rescue Rex::Post::Meterpreter::RequestError => e
        case e.to_s
        when "stdapi_registry_load_key: Operation failed: 1314"
          #print_error("You appear to be lacking the SeRestorePrivilege. Are you running with Admin privs?")
          return false
        when "stdapi_registry_load_key: Operation failed: The system cannot find the path specified."
          #print_error("The path you provided to the Registry Hive does not Appear to be valid: #{file}")
          return false
        when "stdapi_registry_load_key: Operation failed: The process cannot access the file because it is being used by another process."
          #print_error("The file you specified is currently locked by another process: #{file}")
          return false
        when /stdapi_registry_load_key: Operation failed:/
          #print_error("An unknown error has occurred: #{loadres.to_s}")
          return false
        else
          return true
        end
      end

    rescue
      return false
    end
  end

  #
  # Unload the hive file stored in +key+
  #
  def meterpreter_registry_unloadkey(key)
    begin
      client.sys.config.getprivs()
      root_key, base_key = session.sys.registry.splitkey(key)
      begin
        unloadres= session.sys.registry.unload_key(root_key,base_key)
      rescue Rex::Post::Meterpreter::RequestError => e
        case e.to_s
        when "stdapi_registry_unload_key: Operation failed: The parameter is incorrect."
          #print_error("The KEY you provided does not appear to match a loaded Registry Hive: #{key}")
          return false
        when /stdapi_registry_unload_key: Operation failed:/
          #print_error("An unknown error has occurred: #{unloadres.to_s}")
          return false
        else
          return true
        end
      end
    rescue
      return false
    end
  end

  #
  # Create a new registry key
  #
  def meterpreter_registry_createkey(key, view)
    begin
      root_key, base_key = session.sys.registry.splitkey(key)
      perms = meterpreter_registry_perms(KEY_WRITE, view)
      open_key = session.sys.registry.create_key(root_key, base_key, perms)
      open_key.close
      return true
    rescue Rex::Post::Meterpreter::RequestError => e
      return nil
    end
  end

  #
  # Delete the registry value +valname+ store in +key+
  #
  def meterpreter_registry_deleteval(key, valname, view)
    begin
      root_key, base_key = session.sys.registry.splitkey(key)
      perms = meterpreter_registry_perms(KEY_WRITE, view)
      open_key = session.sys.registry.open_key(root_key, base_key, perms)
      open_key.delete_value(valname)
      open_key.close
      return true
    rescue Rex::Post::Meterpreter::RequestError => e
      return nil
    end
  end

  #
  # Delete the registry key +key+
  #
  def meterpreter_registry_deletekey(key, view)
    begin
      root_key, base_key = session.sys.registry.splitkey(key)
      perms = meterpreter_registry_perms(KEY_WRITE, view)
      deleted = session.sys.registry.delete_key(root_key, base_key, perms)
      return deleted
    rescue Rex::Post::Meterpreter::RequestError => e
      return nil
    end
  end

  #
  # Enumerate the subkeys in +key+
  #
  def meterpreter_registry_enumkeys(key, view)
    begin
      subkeys = []
      root_key, base_key = session.sys.registry.splitkey(key)
      perms = meterpreter_registry_perms(KEY_READ, view)
      keys = session.sys.registry.enum_key_direct(root_key, base_key, perms)
      keys.each { |subkey|
        subkeys << subkey
      }
      return subkeys
    rescue Rex::Post::Meterpreter::RequestError => e
      return nil
    end
  end

  #
  # Enumerate the values in +key+
  #
  def meterpreter_registry_enumvals(key, view)
    begin
      values = []
      vals = {}
      root_key, base_key = session.sys.registry.splitkey(key)
      perms = meterpreter_registry_perms(KEY_READ, view)
      vals = session.sys.registry.enum_value_direct(root_key, base_key, perms)
      vals.each { |val|
        values <<  val.name
      }
      return values
    rescue Rex::Post::Meterpreter::RequestError => e
      return nil
    end
  end

  #
  # Get the data stored in the value +valname+
  #
  def meterpreter_registry_getvaldata(key, valname, view)
    begin
      value = nil
      root_key, base_key = session.sys.registry.splitkey(key)
      perms = meterpreter_registry_perms(KEY_READ, view)
      v = session.sys.registry.query_value_direct(root_key, base_key, valname, perms)
      value = v.data
    rescue Rex::Post::Meterpreter::RequestError => e
      return nil
    end
    return value
  end

  #
  # Enumerate the type and data of the value +valname+
  #
  def meterpreter_registry_getvalinfo(key, valname, view)
    value = {}
    begin
      root_key, base_key = session.sys.registry.splitkey(key)
      perms = meterpreter_registry_perms(KEY_READ, view)
      open_key = session.sys.registry.open_key(root_key, base_key, perms)
      v = open_key.query_value(valname)
      value["Data"] = v.data
      value["Type"] = v.type
      open_key.close
    rescue Rex::Post::Meterpreter::RequestError => e
      return nil
    end
    return value
  end

  #
  # Add the value +valname+ to the key +key+ with the specified +type+ and +data+
  #
  def meterpreter_registry_setvaldata(key, valname, data, type, view)
    begin
      root_key, base_key = session.sys.registry.splitkey(key)
      perms = meterpreter_registry_perms(KEY_WRITE, view)
      session.sys.registry.set_value_direct(root_key, base_key,
        valname, session.sys.registry.type2str(type), data, perms)
      return true
    rescue Rex::Post::Meterpreter::RequestError => e
      return nil
    end
  end

  # Checks if a key exists on the target registry using a meterpreter session
  #
  # @param key [String] the full path of the key to check
  # @return [Boolean] true if the key exists on the target registry, false otherwise
  #   (also in case of error)
  def meterpreter_registry_key_exist?(key)
    begin
      root_key, base_key = session.sys.registry.splitkey(key)
    rescue ArgumentError
      return false
    end

    begin
      check = session.sys.registry.check_key_exists(root_key, base_key)
    rescue Rex::Post::Meterpreter::RequestError, TimesoutError
      return false
    end

    check
  end

  #
  # Normalize the supplied full registry key string so the root key is sane.  For
  # instance, passing "HKLM\Software\Dog" will return 'HKEY_LOCAL_MACHINE\Software\Dog'
  #
  def normalize_key(key)
    keys = split_key(key)
    if (keys[0] =~ /HKLM|HKEY_LOCAL_MACHINE/)
      keys[0] = 'HKEY_LOCAL_MACHINE'
    elsif (keys[0] =~ /HKCU|HKEY_CURRENT_USER/)
      keys[0] = 'HKEY_CURRENT_USER'
    elsif (keys[0] =~ /HKU|HKEY_USERS/)
      keys[0] = 'HKEY_USERS'
    elsif (keys[0] =~ /HKCR|HKEY_CLASSES_ROOT/)
      keys[0] = 'HKEY_CLASSES_ROOT'
    elsif (keys[0] =~ /HKCC|HKEY_CURRENT_CONFIG/)
      keys[0] = 'HKEY_CURRENT_CONFIG'
    elsif (keys[0] =~ /HKPD|HKEY_PERFORMANCE_DATA/)
      keys[0] = 'HKEY_PERFORMANCE_DATA'
    elsif (keys[0] =~ /HKDD|HKEY_DYN_DATA/)
      keys[0] = 'HKEY_DYN_DATA'
    else
      raise ArgumentError, "Cannot normalize unknown key: #{key}"
    end
    print_status("Normalized #{key} to #{keys.join("\\")}") if $blab
    return keys.join("\\")
  end

  #
  # Split the supplied full registry key string into its root key and base key.  For
  # instance, passing "HKLM\Software\Dog" will return [ 'HKEY_LOCAL_MACHINE',
  # 'Software\Dog' ]
  #
  def split_key(str)
    if (str =~ /^(.+?)\\(.*)$/)
      [ $1, $2 ]
    else
      [ str, nil ]
    end
  end

end
end
end
end
