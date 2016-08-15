# -*- coding: binary -*-
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'

module Msf
class Post
module Windows

module Dotnet
  include ::Msf::Post::Common
  include ::Msf::Post::Windows::Registry
  
  def initialize(info = {})
    super
    register_advanced_options(
      [
        OptInt.new('Dotnet::Post::timeout',   [true, 'Dotnet execution timeout, set < 0 to run async without termination', 15]),
        OptBool.new('Dotnet::Post::log_output', [true, 'Write output to log file', false]),
        OptBool.new('Dotnet::Post::dry_run', [true, 'Return encoded output to caller', false]),
        OptBool.new('Dotnet::Post::force_wow64', [true, 'Force WOW64 execution', false]),
      ], self.class)
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
    rescue::Exception => e
      print_status("Encountered exception in search_for_version: #{e.class} #{e}")
    end
    subkeys.each do |i|
      if i == 'Version'
        dotnet_version = registry_getvaldata(dotnet_subkey, i)
        break
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
    rescue::Exception => e
      print_status("Encountered exception in get_versionception: #{e.class} #{e}")
    end
    subkeys.each do |i|
      exact_version = search_for_version(dotnet_vkey + '\\' +i)
      unless exact_version.nil?
        #if we find a version, stop looking
        break
      end
    end
    return exact_version
  end
  
  #
  # 'Public' function that returns a list of all .NET versions on
  # a windows host
  #
  def get_dotnet_versions
    ret_val = Array.new
    key = 'HKLM\\SOFTWARE\\Microsoft\NET Framework Setup\\NDP'
    begin
      dotnet_keys = registry_enumkeys(key)
    rescue::Exception => e
      print_status("Encountered exception in get_dotnet_version: #{e.class} #{e}")
    end
    unless dotnet_keys.nil?
      dotnet_keys.each do |i|
        if i[0,1] == 'v'
          key = 'HKLM\\SOFTWARE\\Microsoft\NET Framework Setup\\NDP\\'+i
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
end
end
end
