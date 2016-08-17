# -*- coding: binary -*-
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'

module Msf::Post::Windows::Dotnet
  include ::Msf::Post::Common
  include ::Msf::Post::Windows::Registry

  def initialize(info = {})
    super
  end
  #
  # Searches the subkey for the value 'Version' which contains the
  # actual version, rather than the over-arching release
  # An alternative would be to query for it, and catch the exception.
  #
  
  def search_for_version(dotnet_subkey)
    dotnet_version = nil
    begin
      subkeys = registry_enumvals(dotnet_subkey)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_status("Encountered exception in search_for_version: #{e.class} #{e}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end
    unless subkeys.nil?
      subkeys.each do |subkey|
        if subkey == 'Version'
          dotnet_version = registry_getvaldata(dotnet_subkey, subkey)
          break
        end
      end
    end
    return dotnet_version
  end

  #
  # Bruteforce search all subkeys in an over-arching release to
  # locate the actual release version.
  #
  def get_versionception(dotnet_vkey)
    exact_version = nil
    begin
      subkeys = registry_enumkeys(dotnet_vkey)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_status("Encountered exception in get_versionception: #{e.class} #{e}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end
    unless subkeys.nil?
      subkeys.each do |subkey|
        exact_version = search_for_version(dotnet_vkey + '\\' + subkey)
        unless exact_version.nil?
          # if we find a version, stop looking
          break
        end
      end
    end
    return exact_version
  end
  
  #
  # 'Public' function that returns a list of all .NET versions on
  # a windows host
  #
  def get_dotnet_versions
    ret_val = []
    key = 'HKLM\\SOFTWARE\\Microsoft\NET Framework Setup\\NDP'
    begin
      dotnet_keys = registry_enumkeys(key)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_status("Encountered exception in get_dotnet_version: #{e.class} #{e}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end
    unless dotnet_keys.nil?
      dotnet_keys.each do |temp_key|
        if temp_key[0] == 'v'
          key = 'HKLM\\SOFTWARE\\Microsoft\NET Framework Setup\\NDP\\' + temp_key
          dotnet_version = get_versionception(key)
          unless dotnet_version.nil? 
            ret_val << dotnet_version
          end
        end
      end
    end
    return ret_val
  end
end

