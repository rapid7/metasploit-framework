#!/usr/bin/env ruby
#
# $Id$
#
# This script acts as a small registry reader.
# You may easily automate a lot of registry forensics with a proper method.
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'rex/registry/hive'

def print_all(nodekey)
  print_all_keys(nodekey)
  print_all_values(nodekey)
end

def print_all_keys(nodekey)

  return if !nodekey
  return if !nodekey.lf_record
  return if !nodekey.lf_record.children
  return if nodekey.lf_record.children.length == 0

table = Rex::Ui::Text::Table.new(
  'Header'  => "Child Keys for #{nodekey.full_path}",
  'Indent'  => '    '.length,
  'Columns' => [ 'Name', 'Last Edited', 'Subkey Count', 'Value Count' ]
  )

  if nodekey.lf_record && nodekey.lf_record.children && nodekey.lf_record.children.length > 0
    nodekey.lf_record.children.each do |key|
      table << [key.name, key.readable_timestamp, key.subkeys_count, key.value_count]
    end
  end

  puts table.to_s
  end

  def print_all_values(nodekey)

    return if !nodekey
    return if !nodekey.lf_record
    return if !nodekey.lf_record.children
    return if nodekey.lf_record.children.length == 0

    table = Rex::Ui::Text::Table.new(
      'Header' => "Values in key #{nodekey.full_path}",
      'Indent' => '    '.length,
      'Columns' => ['Name','Value Type', 'Value']
      )
    if nodekey.value_list && nodekey.value_list.values.length > 0
    nodekey.value_list.values.each do |value|
    table << [value.name, value.readable_value_type, value.value.data]
    end
  end

  puts table.to_s
end

def get_system_information
  if @hive.hive_name =~ /SYSTEM/
    mounted_devices_info_key = @hive.relative_query("\\MountedDevices")

    current_control_set_key = @hive.value_query('\Select\Default')
    current_control_set = "ControlSet00" + current_control_set_key.value.data.unpack('c').first.to_s if current_control_set_key

    computer_name_key = @hive.value_query("\\" + current_control_set + "\\Control\\ComputerName\\ComputerName") if current_control_set
    computer_name = computer_name_key.value.data.to_s if computer_name_key

    event_log_info_key = @hive.relative_query("\\" + current_control_set + "\\Services\\EventLog") if current_control_set

    puts "Computer Name: " + computer_name if computer_name

    print_all_values(event_log_info_key) if event_log_info_key
    puts "-----------------------------------------" if event_log_info_key

    print_all_values(mounted_devices_info_key) if mounted_devices_info_key
    puts "-----------------------------------------" if mounted_devices_info_key

  elsif @hive.hive_name =~ /SOFTWARE/
    current_version_info_key = @hive.relative_query("\\Microsoft\\Windows NT\\CurrentVersion")
    login_info_key = @hive.relative_query("\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")

    print_all_values(current_version_info_key)
    puts "-----------------------------------------" if current_version_info_key

    print_all_values(login_info_key)
    puts "-----------------------------------------" if login_info_key
  end
end

def get_user_information


  local_groups_info_key = @hive.relative_query("\\SAM\\Domains\\Builtin\\Aliases\\Names")
  local_users_info_key = @hive.relative_query("\\SAM\\Domains\\Account\\Users\\Names")

  print_all(local_groups_info_key)
  puts "------------------------------------------------" if local_groups_info_key && local_groups_info_key.lf_record.children

  print_all(local_users_info_key)
  puts "------------------------------------------------" if local_users_info_key && local_groups_info_key.lf_record.children
end

def dump_creds
end

def get_boot_key

    return if !@hive.root_key
    return if !@hive.root_key.name

    puts "Getting boot key"
    puts "Root key: " + @hive.root_key.name

    default_control_set = @hive.value_query('\Select\Default').value.data.unpack("c").first

    puts "Default ControlSet: ControlSet00#{default_control_set}"

    bootkey = ""
    basekey = "\\ControlSet00#{default_control_set}\\Control\\Lsa"

    %W{JD Skew1 GBG Data}.each do |k|
      ok = @hive.relative_query(basekey + "\\" + k)
      return nil if not ok

      tmp = ""
      0.upto(ok.class_name_length - 1) do |i|
        next if i%2 == 1

        tmp << ok.class_name_data[i,1]
      end

      bootkey << [tmp.to_i(16)].pack('V')
    end


    keybytes    = bootkey.unpack("C*")

    descrambled = ""
  #	descrambler = [ 0x08, 0x05, 0x04, 0x02, 0x0b, 0x09, 0x0d, 0x03, 0x00, 0x06, 0x01, 0x0c, 0x0e, 0x0a, 0x0f, 0x07 ]
    descrambler = [ 0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04 ]

    0.upto(keybytes.length-1) do |x|
      descrambled << [ keybytes[ descrambler[x] ] ].pack("C")
    end

    puts descrambled.unpack("H*")
end

def list_applications
end

def list_drivers
end

def get_aol_instant_messenger_information

  if @hive.hive_name != /NTUSER\.dat/i
    users_list_key = @hive.relative_query('\Software\America Online\AOL Instant Messenger(TM)\CurrentVersion\Users')
    last_logged_in_user_key = @hive.relative_query("\\Software\\America Online\\AOL Instant Messenger(TM)\\CurrentVersion\\Login - Screen Name")

    print_all_keys(users_list_key)

    users_list_key.lf_record.children.each do |screenname|
      away_messages_key = @hive.relative_query("\\Software\\America Online\\AOL Instant Messenger(TM)\\CurrentVersion\\Users\\#{screenname.name}\\IAmGoneList")
      file_xfer_settings_key = @hive.relative_query("\\Software\\America Online\\AOL Instant Messenger(TM)\\CurrentVersion\\Users\\#{screenname.name}\\Xfer")
      profile_info_key = @hive.relative_query("\\Software\\America Online\\AOL Instant Messenger(TM)\\CurrentVersion\\Users\\#{screenname.name}\\DirEntry")
      recent_contacts_key = @hive.relative_query("\\Software\\America Online\\AOL Instant Messenger(TM)\\CurrentVersion\\Users\\#{screenname.name}\\Recent IM ScreenNames")

      print_all(away_messages_key)
      print_all(file_xfer_settings_key)
      print_all(profile_info_key)
      print_all(recent_contacts_key)
    end

  end
end

def get_msn_messenger_information

  if @hive.hive_name =~ /NTUSER\.dat/i
    general_information_key = @hive.relative_query("\\Software\\Microsoft\\MessengerService\\ListCache\\.NETMessengerService\\")
    file_sharing_information_key = @hive.relative_query("\\Software\\Microsoft\\MSNMessenger\\FileSharing - Autoshare")
    file_transfers_information_key = @hive.relative_query("\\Software\\Microsoft\\MSNMessenger\\ - FTReceiveFolder")

    print_all(general_information_key)
    print_all(file_sharing_information_key)
    print_all(file_transfers_information_key)
  end
end

def get_windows_messenger_information
  if @hive.hive_name =~ /NTUSER\.dat/i
    contact_list_information_key = @hive.relative_query("\\Software\\Microsoft\\MessengerService\\ListCache\\.NET Messenger Service")
    file_transfers_information_key = @hive.relative_query("\\Software\\Microsoft\\Messenger Service - FtReceiveFolder")
    last_user_information_key = @hive.relative_query("\\Software\\Microsoft\\MessengerService\\ListCache\\.NET Messenger Service - IdentityName")

    print_all(contact_list_information_key)
    print_all(file_transfers_information_key)
    print_all(last_user_information_key)
  end
end

def get_icq_information
  if @hive.hive_name =~ /NTUSER\.dat/i
    general_information_key = @hive.relative_query("\\Software\\Mirabalis\\ICQ")

    print_all(general_information_key)
  elsif @hive.hive_name =~ /SOFTWARE/
    owner_number_key = @hive.relative_query("\\Software\\Mirabalis\\ICQ\\Owner")
    print_all(owner_number_key)
  end
end

def get_ie_information
  if @hive.hive_name =~ /NTUSER\.dat/i
    stored_logon_information_key = @hive.relative_query("\\Software\\Microsoft\\Protected Storage System Provider\\SID\\Internet Explorer\\Internet Explorer - URL:StringData")
    stored_search_terms_information_key = @hive.relative_query("\\Software\\Microsoft\\Protected Storage SystemProvider\\SID\\Internet Explorer\\Internet Explorer - q:SearchIndex")
    ie_setting_information_key = @hive.relative_query("\\Software\\Microsoft\\Internet Explorer\\Main")
    history_length_value_key = @hive.value_query("\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\URL History - DaysToKeep")
    typed_urls_information_key = @hive.relative_query("\\Software\\Microsoft\\Internet Explorer\\Typed URLs")
    intelliforms_information_key = @hive.relative_query("\\Software\\Microsoft\\Internet Explorer\\Intelliforms")
    autocomplete_web_addresses_key = @hive.relative_query("\\Software\\Microsoft\\Protected Storage System Provider")
    default_download_dir = @hive.relative_query("\\Software\\Microsoft\\Internet Explorer")

    print_all(stored_logon_information_key)
    print_all(stored_search_terms_information_key)
    print_all(ie_setting_information_key)
    print_all(typed_urls_information_key)
    print_all(intelliforms_information_key)
    print_all(autocomplete_web_addresses_key)
    print_all(default_download_dir)

    puts "Days saved in history: " + history_length_value_key.value.data.to_s if !history_length_value_key.kind_of? Array
  end
end

def get_outlook_information
  if @hive.hive_name =~ /NTUSER\.dat/i
    account_information_key = @hive.relative_query("\\Software\\Microsoft\\Protected Storage System Provider\\SID\\Identification\\INETCOMM Server Passwords")

    print_all(account_information_key)
  end
end

def get_yahoo_messenger_information
  if @hive.hive_name =~ /NTUSER\.dat/i
    profiles_key = @hive.relative_query("\\Software\\Yahoo\\Pager\\profiles")

    print_all(profiles_key)

    profiles_key.lf_record.children.each do |child|
      file_transfers_information_key = @hive.relative_query("\\Software\\Yahoo\\Pager\\profiles\\#{child.name}\\FileTransfer")
      message_archiving_information_key = @hive.relative_query("\\Software\\Yahoo\\Pager\\profiles\\#{child.name}\\Archive")

      print_all(file_transfers_information_key)
      print_all(message_archiving_information_key)
    end
  end
end

def get_networking_information

end

def get_user_application_information
end

if ARGV.length == 0 || ARGV[0] == "help"
  no_args = %Q{
Usage: reg.rb <command> <opts> <hivepath>

Available commands:
  query_key                               Query for more information about a specific node key
  query_value                             Query for the value of a specific value key
  get_boot_key                            Extract the boot key from the SYSTEM hive
  dump_creds                              Dump the usernames and password hashes of the users from the SAM hive
  list_applications                       List all the applications installed via the SOFTWARE hive
  list_drivers                            List all the devices and their respective drivers and driver versions from SYSTEM hive
  get_everything                          When pointed to a directory with hives, it will run all commands on all available hives
  get_aol_instant_messenger_information   Get credentials and general information on AOL Instant Messenger users from NTUSER.dat
  get_msn_messenger_information           Get credentials and general information on MSN Messenger users from NTUSER.dat
  get_windows_messenger_information       Get credentials and general information on Windows Messenger users from NTUSER.dat
  get_icq_information                     Get credentials and general information on ICQ users from NTUSER.dat
  get_ie_information                      Get stored credentials, typed history, search terms, and general settings from NTUSER.dat
  get_outlook_information                 Gets outlook and outlook express stored credentials and general information from NTUSER.dat
  get_yahoo_messenger_information         Gets credentials and general information on Yahoo! Messenger users from NTUSER.dat
  get_system_information                  Gets general system administration from both SOFTWARE and SYSTEM hives
  get_networking_information              Gets networing information from the SAM, SYSTEM, and NTUSER.dat hives
  get_user_information                    Gets general user information from the SYSTEM, SECURITY, SAM, and NTUSER.dat hives
  get_user_application_information        Gets user-specific application information from the NTUSER.DAT and SOFTWARE hives
  }

  puts no_args
  exit
end


case ARGV[0]

when "query_key"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
  puts "Hive name: #{@hive.hive_name}"

  1.upto(ARGV.length - 2) do |arg|
    selected = @hive.relative_query(ARGV[arg])
    print_all(selected)
  end

when "query_value"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
  puts "Hive name: #{@hive.hive_name}"

  1.upto(ARGV.length - 2) do |i|
    selected = @hive.value_query(ARGV[i])

    if !selected
      puts "Value not found."
      return
    end

    puts "Value Name: #{selected.name}"
    puts "Value Data: #{selected.value.data.inspect}"
  end

when "get_boot_key"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /SYSTEM/
    puts "I need a SYSTEM hive to grab the boot key, not a #{@hive.hive_name}."
  else
    get_boot_key
  end

when "dump_creds"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /SAM/
    puts "I need a SAM hive, not a #{@hive.hive_name}"
  else
    dump_creds
  end

when "list_applications"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /SOFTWARE/
    puts "I need a SOFTWARE hive, not a #{@hive.hive_name}."
  else
    list_applications
  end

when "list_drivers"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /SYSTEM/
    puts "I need a SYSTEM hive, not a #{@hive.hive_name}."
  else
    list_drivers
  end

when "get_everything"
  Dir.foreach(ARGV[1]) do |file|
  next if file =~ /^\./
  next if ::File.directory?(ARGV[1] + "/" + file)

  @hive = Rex::Registry::Hive.new(ARGV[1] + "/" + file)

  next if !@hive.hive_regf
  next if !@hive.hive_name

  case @hive.hive_name

  when /SYSTEM/

    puts "Found a SYSTEM hive..."

    list_drivers
    get_boot_key
    get_system_information
    get_networking_information
    get_user_information

  when /SOFTWARE/

    puts "Found a SOFTWARE hive..."

    list_applications
    get_icq_information
    get_system_information
    get_networking_information
    get_user_information
    get_user_application_information

  when /SAM/

    puts "Found a SAM hive..."

    get_networking_information
    get_user_information

  when /SECURITY/

    puts "Found a SECURITY hive..."

    get_user_information

  when /NTUSER\.dat/i

    puts "Found a NTUSER.dat hive..."

    get_aol_instant_messenger_information
    get_icq_information
    get_ie_information
    get_msn_messenger_information
    get_outlook_information
    get_windows_messenger_information
    get_yahoo_messenger_information
    get_networking_information
    get_user_information
    get_user_application_information

  end
end

when "get_aol_instant_messenger_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /NTUSER\.DAT/i
    puts "I need the NTUSER.dat hive, not #{@hive.hive_name}."
  else
    get_aol_instant_messenger_information
  end

when "get_icq_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /NTUSER\.dat/i && @hive.hive_name !~ /SOFTWARE/
    puts "I need either a SOFTWARE or NTUSER.dat hive, not #{@hive.hive_name}."
  else
    get_icq_information
  end

when "get_ie_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /NTUSER\.dat/i
    puts "I need an NTUSER.dat hive, not #{@hive.hive_name}."
  else
    get_ie_information
  end

when "get_msn_messenger_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /NTUSER\.dat/i
    puts "I need an NTUSER.dat hive, not #{@hive.hive_name}."
  else
    get_msn_messenger_information
  end

when "get_outlook_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /NTUSER\.dat/i
    puts "I need an NTUSER.dat hive, not #{@hive.hive_name}."
  else
    get_outlook_information
  end

when "get_windows_messenger_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /NTUSER\.dat/i
    puts "I need an NTUSER.dat hive, not a #{@hive.hive_name}."
  else
    get_windows_messenger_information
  end

when "get_yahoo_messenger_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /NTUSER\.dat/i
    puts "I need an NTUSER.dat hive, not a #{@hive.hive_name}."
  else
    get_yahoo_messenger_information
  end

when "get_system_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /SYSTEM/ && @hive.hive_name !~ /SOFTWARE/
    puts "I need the SYSTEM or SOFTWARE hive, not #{@hive.hive_name}."
  else
    get_system_information
  end

when "get_networking_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /SAM/ && @hive.hive_name !~ /SYSTEM/ && @hive.hive_name !~ /NTUSER\.dat/i
    puts "I need either a SAM, SYSTEM, or NTUSER.dat hive, not a #{@hive.hive_name}."
  else
    get_networking_information
  end

when "get_user_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /SAM/
    puts "I need a SAM hive. Not a #{@hive.hive_name}."
  else
    get_user_information
  end

when "get_user_application_information"
  @hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

  if @hive.hive_name !~ /NTUSER\.dat/i && @hive.hive_name !~ /SOFTWARE/
    puts "I need either an NTUSER.dat or SOFTWARE hive, not a #{@hive.hive_name}."
  else
    get_user_application_information
  end

else
  puts "Sorry invalid command, try with \"help\""
end
