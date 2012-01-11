#!/usr/bin/env ruby
#
# $Id$
#
# This script acts as a small registry reader.
# You may easily automate a lot of registry forensics with a proper method.
# $Revision$
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'rex/registry/hive'

def print_all(nodekey)
	print_all_keys(nodekey)
	print_all_values(nodekey)
end

def print_all_keys(nodekey)
	table = Rex::Ui::Text::Table.new(
        	'Header'  => "Child Keys for #{nodekey.full_path}",
        	'Indent'  => '    '.length,
        	'Columns' => [ 'Name', 'Last Edited', 'Subkey Count', 'Value Count' ]
	)

        if nodekey.lf_record && nodekey.lf_record.children.length > 0
                nodekey.lf_record.children.each do |key|
                        table << [key.name, key.readable_timestamp, key.subkeys_count, key.value_count]
                end
        end

	puts table.to_s
end

def print_all_values(nodekey)

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
	if @hive.hive_regf.hive_name =~ /SYSTEM/
		mounted_devices_info_key = @hive.relative_query("\\MountedDevices")

		current_control_set_key = @hive.value_query('\Select\Default')
		current_control_set = "ControlSet00" + current_control_set_key.value.data.unpack('c').first.to_s
	
		computer_name_key = @hive.value_query("\\" + current_control_set + "\\Control\\ComputerName\\ComputerName")
		computer_name = computer_name_key.value.data.to_s
		
		event_log_info_key = @hive.relative_query("\\" + current_control_set + "\\Services\\EventLog")
	
		puts "Computer Name: " + computer_name
	
		print_all_values(event_log_info_key)
		puts "-----------------------------------------"

		print_all_values(mounted_devices_info_key)
		puts "-----------------------------------------"

	elsif @hive.hive_regf.hive_name =~ /SOFTWARE/
		current_version_info_key = @hive.relative_query("\\Microsoft\\Windows NT\\CurrentVersion")
		login_info_key = @hive.relative_query("\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")

		print_all_values(current_version_info_key)
		puts "-----------------------------------------"

		print_all_values(login_info_key)
		puts "-----------------------------------------"
	end
end

def get_user_information
	local_groups_info_key = @hive.relative_query("\\SAM\\Domains\\Builtin\\Aliases\\Names")
	local_users_info_key = @hive.relative_query("\\SAM\\Domains\\Account\\Users\\Names")	

	print_all_keys(local_groups_info_key)
	puts "------------------------------------------------"

	print_all_keys(local_users_info_key)
	puts "------------------------------------------------"
end

def dump_creds
end

def get_boot_key
end

def list_applications
end

def list_drivers
end

def get_aol_instant_messenger_information
	
	if @hive.hive_regf.hive_name != /NTUSER[.]dat/i
		users_list_key = @hive.relative_query('\Software\America Online\AOL Instant Messenger(TM)\CurrentVersion\Users')
                last_logged_in_user_key = @hive.relative_query("\\Software\\America Online\\AOL Instant Messenger(TM)\\CurrentVersion\\Login - Screen Name")

		print_all_keys(user_list_key)

		user_list_key.lf_record.children.each do |screenname|
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

	if @hive.hive_regf.hive_name =~ /NTUSER[.]dat/i
		general_information_key = @hive.relative_query("\\Software\\Microsoft\\MessengerService\\ListCache\\.NETMessengerService\\")
		file_sharing_information_key = @hive.relative_query("\\Software\\Microsoft\\MSNMessenger\\FileSharing - Autoshare")
		file_transfers_information_key = @hive.relative_query("\\Software\\Microsoft\\MSNMessenger\\ - FTReceiveFolder")

		print_all(general_information_key)
		print_all(file_sharing_information_key)
		print_all(file_transfers_information_key)
	end	
end

def get_windows_messenger_information
	if @hive.hive_regf.hive_name =~ /NTUSER[.]dat/i
		contact_list_information_key = @hive.relative_query("\\Software\\Microsoft\\MessengerService\\ListCache\\.NET Messenger Service")
		file_transfers_information_key = @hive.relative_query("\\Software\\Microsoft\\Messenger Service - FtReceiveFolder")
		last_user_information_key = @hive.relative_query("\\Software\\Microsoft\\MessengerService\\ListCache\\.NET Messenger Service - IdentityName")

		print_all(contact_list_information_key)
		print_all(file_transers_information_key)
		print_all(last_user_information_key)
	end
end

def get_icq_information
	if @hive.hive_regf.hive_name != /NTUSER[.]dat/i
		general_information_key = @hive.relative_query("\\Software\\Mirabalis\\ICQ")
		
		print_all(general_information_key)
	elsif @hive.hive_regf.hive_name != /SOFTWARE/
		owner_number_key = @hive.value_query("\\Software\\Mirabalis\\ICQ\\Owner")

		puts "Owner UIN: #{owner_number_key.value.data.to_s}"
	end
end

def get_ie_information
	if @hive.hive_regf.hive_name =~ /NTUSER[.]dat/i
		stored_logon_information_key = @hive.relative_query("\\Software\\Microsoft\\Protected Storage System Provider\\SID\\Internet Explorer\\Internet Explorer - URL:StringData")
		stored_search_terms_information_key = @hive.relative_quety("\\Software\\Microsoft\\Protected Storage SystemProvider\\SID\\Internet Explorer\\Internet Explorer - q:SearchIndex")
		ie_setting_information_key = @hive.relative_query("\\Software\\Microsoft\\Internet Explorer\\Main")
		history_length_value_key = @hive.value_query("\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\URL History - DaysToKeep")
		typed_urls_information_key = @hive.relative_query("\\Software\\Microsoft\\Internet Explorer\\Typed URLs")
		intelliforms_information_key = @hive.relative_query("\\Software\\Microsoft\\Internet Explorer\\Intelliforms")
		autocomplete_web_addresses_key = @hive.relative_query("\\Software\\Microsoft\\Protected Storage System Provider")
		default_download_dir = @hive.relative_query("\\Software\\Microsoft\\Internet Explorer")
		
		print_all(stored_logon_information_key)
		print_all(stored_search_terms_information_key)
		print_all(ie_settings_information_key)
		print_all(type_urls_information_key)
		print_all(intelliforms_information_key)
		print_all(autocomplete_web_addresses_key)
		print_all(default_download_dir)

		puts "Days saved in history: " + history_length_value_key.value.data.to_s
	end
end

def get_outlook_information
	if @hive.hive_regf.hive_name =~ /NTUSER[.]dat/i
		account_information_key = @hive.relative_query("\\Software\\Microsoft\\Protected Storage System Provider\\SID\\Identification\\INETCOMM Server Passwords")
		
		print_all(account_information_key)
	end
end

def get_yahoo_messenger_information
	if @hive.hive_regf.hive_name =~ /NTUSER[.]dat/i
		profiles_key = @hive.relative_query("\\Software\\Yahoo\\Pager\\profiles")

		print_all(profiles_key)

		profiles_key.lf_record.children.each do |child|
			file_transfers_information_key = @hive.relative_query("\\Software\\Yahoo\\Pager\\profiles\\#{child.name}\\FileTransfer")
			message_archiving_information_key = @hive.relative_query("\\Software\\Yahoo\\Pager\\profiles\\#{child.name}\\Archive")
			
			print_all(file_transfer_information_key)
			print_all(message_archiving_information_key)
		end
	end
end

def get_networking_information
	
end

def get_user_information
end

def get_user_application_information
end

if ARGV.length == 0 || ARGV[0] == "help"
	no_args = %Q{
Usage: reg.rb <command> <opts> <hivepath>

Available commands:
    query_key					Query for more information about a specific node key
    query_value					Query for the value of a specific value key
    get_boot_key				Extract the boot key from the SYSTEM hive
    dump_creds					Dump the usernames and password hashes of the users from the SAM hive
    list_applications				List all the applications installed via the SOFTWARE hive
    list_drivers				List all the devices and their respective drivers and driver versions from SYSTEM hive
    get_everything				When pointed to a directory with hives, it will run all commands on all available hives
    get_aol_instant_messenger_information	Get credentials and general information on AOL Instant Messenger users from NTUSER.dat
    get_msn_messenger_information		Get credentials and general information on MSN Messenger users from NTUSER.dat
    get_windows_messenger_information		Get credentials and general information on Windows Messenger users from NTUSER.dat
    get_icq_information				Get credentials and general information on ICQ users from NTUSER.dat
    get_ie_information				Get stored credentials, typed history, search terms, and general settings from NTUSER.dat
    get_outlook_information			Gets outlook and outlook express stored credentials and general information from NTUSER.dat
    get_yahoo_messenger_information		Gets credentials and general information on Yahoo! Messenger users from NTUSER.dat
    get_system_information			Gets general system administration from both SOFTWARE and SYSTEM hives
    get_networking_information			Gets networing information from the SAM, SYSTEM, and NTUSER.dat hives
    get_user_information			Gets general user information from the SYSTEM, SECURITY, SAM, and NTUSER.dat hives
    get_user_application_information		Gets user-specific application information from the NTUSER.DAT and SOFTWARE hives
	}

	puts no_args
elsif ARGV[0] == "query_key"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	puts "Hive name: #{@hive.hive_regf.hive_name}"
	
	1.upto(ARGV.length - 2) do |arg|
		selected = @hive.relative_query(ARGV[arg])
		
		print_all(selected)
	end
elsif ARGV[0] == "query_value"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	puts "Hive name: #{@hive.hive_regf.hive_name}"

	1.upto(ARGV.length - 2) do |i|
		selected = @hive.value_query(ARGV[i])

		if !selected
			puts "Value not found."
			return
		end

		puts "Value Name: #{selected.name}"
		puts "Value Data: #{selected.value.data.inspect}"
	end
elsif ARGV[0] == "get_boot_key"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	
	if @hive.hive_regf.hive_name !~ /SYSTEM/
		puts "I need a SYSTEM hive to grab the boot key, not a #{@hive.hive_regf.hive_name}."
	else
		get_boot_key
	end

elsif ARGV[0] == "dump_creds"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

	if @hive.hive_regf.hive_name !~ /SAM/
		puts "I need a SAM hive, not a #{@hive.hive_regf.hive_name}"
	else
		dump_creds
	end

elsif ARGV[0] == "list_applications"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

	if @hive.hive_regf.hive_name !~ /SOFTWARE/
		puts "I need a SOFTWARE hive, not a #{@hive.hive_regf.hive_name}."
	else
		list_applications
	end

elsif ARGV[0] == "list_drivers"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	
	if @hive.hive_regf.hive_name !~ /SYSTEM/
		puts "I need a SYSTEM hive, not a #{@hive.hive_regf.hive_name}."
	else
		list_drivers
	end

elsif ARGV[0] == "get_everything"
	Dir.foreach(ARGV[1]) do |file|
		next if file =~ /^[.]/

		@hive = Rex::Registry::Hive.new(ARGV[1] + "/" + file)

		if @hive.hive_regf.hive_name =~ /SYSTEM$/
			
			list_drivers
			get_boot_key
			get_system_information
			get_networking_information
			get_user_information

		elsif @hive.hive_regf.hive_name =~ /SOFTWARE$/
			
			list_applications
			get_icq_information
			get_system_information
			get_networking_information
			get_user_information
			get_user_application_information
			
		elsif @hive.hive_regf.hive_name =~ /SAM$/

			get_networking_information
			get_user_information

		elsif @hive.hive_regf.hive_name =~ /SECURITY$/

			get_user_information

		elsif @hive.hive_regf_hive_name =~ /NTUSER[.]dat$/i

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

elsif ARGV[0] == "get_aol_instant_messenger_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

	if @hive.hive_regf.hive_name !~ /NTUSER[.]DAT/i
		puts "I need the NTUSER.dat hive, not #{@hive.hive_regf.hive_name}."
	else
		get_aol_instant_messenger_information
	end

elsif ARGV[0] == "get_icq_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

	if @hive.hive_regf.hive_name !~ /NTUSER[.]dat/i && @hive.hive_regf.hive_name !~ /SOFTWARE/
		puts "I need either a SOFTWARE or NTUSER.dat hive, not #{@hive.hive_regf.hive_name}."
	else
		get_icq_information
	end
elsif ARGV[0] == "get_ie_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	
	if @hive.hive_regf.hive_name !~ /NTUSER[.]dat/i
		puts "I need an NTUSER.dat hive, not #{@hive.hive_regf.hive_name}."
	else
		get_ie_information
	end

elsif ARGV[0] == "get_msn_messenger_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	
	if @hive.hive_regf.hive_name !~ /NTUSER[.]dat/i
		puts "I need an NTUSER.dat hive, not #{@hive.hive_regf.hive_name}."
	else
		get_msn_messenger_information
	end

elsif ARGV[0] == "get_outlook_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

	if @hive.hive_regf.hive_name !~ /NTUSER[.]dat/i
		puts "I need an NTUSER.dat hive, not #{@hive.hive_regf.hive_name}."
	else
		get_outlook_information
	end

elsif ARGV[0] == "get_windows_messenger_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

	if @hive.hive_regf.hive_name !~ /NTUSER[.]dat/i
		puts "I need an NTUSER.dat hive, not a #{@hive.hive_regf.hive_name}."
	else
		get_windows_messenger_information
	end

elsif ARGV[0] == "get_yahoo_messenger_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	
	if @hive.hive_regf.hive_name !~ /NTUSER[.]dat/i
		puts "I need an NTUSER.dat hive, not a #{@hive.hive_regf.hive_name}."
	else
		get_yahoo_messenger_information
	end

elsif ARGV[0] == "get_system_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	
	if @hive.hive_regf.hive_name !~ /SYSTEM/ && @hive.hive_regf.hive_name !~ /SOFTWARE/
		puts "I need the SYSTEM or SOFTWARE hive, not #{@hive.hive_regf.hive_name}."
	else
		get_system_information		
	end	
elsif ARGV[0] == "get_networking_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])

	if @hive.hive_regf.hive_name !~ /SAM/ && @hive.hive_regf.hive_name !~ /SYSTEM/ && @hive.hive_regf.hive_name !~ /NTUSER[.]dat/i
		puts "I need either a SAM, SYSTEM, or NTUSER.dat hive, not a #{@hive.hive_regf.hive_name}."
	else
		get_networking_information
	end

elsif ARGV[0] == "get_user_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	
	if @hive.hive_regf.hive_name !~ /SAM/
		puts "I need a SAM hive. Not a #{@hive.hive_regf.hive_name}."
	else
		get_user_information
	end
elsif ARGV[0] == "get_user_application_information"
	@hive = Rex::Registry::Hive.new(ARGV[ARGV.length - 1])
	
	if @hive.hive_regf.hive_name !~ /NTUSER[.]dat/i && @hive.hive_regf.hive_name !~ /SOFTWARE/
		puts "I need either an NTUSER.dat or SOFTWARE hive, not a #{@hive.hive_regf.hive_name}."
	else
		get_user_application_information
	end
end
