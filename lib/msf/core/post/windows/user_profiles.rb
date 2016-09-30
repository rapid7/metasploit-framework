# -*- coding: binary -*-
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/accounts'

module Msf
class Post
module Windows

module UserProfiles
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Accounts

  #
  # Load the registry hive for each user on the machine and parse out the
  # user profile information. Next, unload the hives we loaded and return
  # the user profiles.
  #
  def grab_user_profiles
    hives = load_missing_hives()
    profiles = parse_profiles(hives)
    unload_our_hives(hives)
    return profiles
  end

  #
  # Unload any hives we loaded.
  #
  def unload_our_hives(hives)
    hives.each do |hive|
      next unless hive['OURS']==true
      registry_unloadkey(hive['HKU'])
    end
  end

  #
  # Return a list of user profiles parsed each of the hives in +hives+.
  #
  def parse_profiles(hives)
    profiles=[]
    hives.each do |hive|
      profile = parse_profile(hive)
      profiles << profile
    end
    return profiles
  end

  #
  # Get the user profile information from the hive specified by +hive+
  #
  def parse_profile(hive)
    profile={}
    profile['SID'] = hive['SID']
    profile['ProfileDir'] = hive['PROF']
    profile['AppData'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'AppData')
    profile['LocalAppData'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Local AppData')
    profile['LocalSettings'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Local Settings')
    profile['Desktop'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Desktop')
    profile['MyDocs'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Personal')
    profile['Favorites'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Favorites')
    profile['History'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'History')
    profile['Cookies'] = registry_getvaldata("#{hive['HKU']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 'Cookies')
    profile['Temp'] = registry_getvaldata("#{hive['HKU']}\\Environment", 'TEMP').to_s.sub('%USERPROFILE%',profile['ProfileDir'])
    profile['Path'] = registry_getvaldata("#{hive['HKU']}\\Environment", 'PATH')

    sidinf = resolve_sid(hive['SID'].to_s)
    if sidinf
      profile['UserName'] = sidinf[:name]
      profile['Domain'] = sidinf[:domain]
    end

    return profile
  end

  #
  # Load any user hives that are not already loaded.
  #
  def load_missing_hives
    hives=[]
    read_profile_list().each do |hive|
      hive['OURS']=false
      if hive['LOADED']== false
        if session.fs.file.exist?(hive['DAT'])
          hive['OURS'] = registry_loadkey(hive['HKU'], hive['DAT'])
          print_error("Error loading USER #{hive['SID']}: Hive could not be loaded, are you Admin?") unless hive['OURS']
        else
          print_error("Error loading USER #{hive['SID']}: Profile doesn't exist or cannot be accessed")
        end
      end
      hives << hive
    end
    return hives
  end

  #
  # Read HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList to
  # get a list of user profiles on the machine.
  #
  def read_profile_list
    hives=[]
    registry_enumkeys('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').each do |profkey|
      next unless profkey.include? "S-1-5-21"
      hive={}
      hive['SID']=profkey
      hive['HKU']= "HKU\\#{profkey}"
      hive['PROF']= registry_getvaldata("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\#{profkey}", 'ProfileImagePath')
      hive['PROF']= session.fs.file.expand_path(hive['PROF']) if hive['PROF']
      hive['DAT']= "#{hive['PROF']}\\NTUSER.DAT"
      hive['LOADED'] = loaded_hives.include?(profkey)
      hives << hive
    end
    return hives
  end

  #
  # Return a list of loaded registry hives.
  #
  def loaded_hives
    hives=[]
    registry_enumkeys('HKU').each do |k|
      next unless k.include? "S-1-5-21"
      next if k.include? "_Classes"
      hives<< k
    end
    return hives
  end

end
end
end
end

