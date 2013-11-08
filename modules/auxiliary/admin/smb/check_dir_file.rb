##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize
    super(
      'Name'        => 'SMB Scanner Check File/Directory Utility',
      'Description' => %Q{
        This module is useful when checking an entire network
        of SMB hosts for the presence of a known file or directory.
        An example would be to scan all systems for the presence of
        antivirus or known malware outbreak. Typically you must set
        RPATH, SMBUser, SMBDomain and SMBPass to operate correctly.
      },
      'Author'      =>
        [
          'patrick',
        ],
      'References'  =>
        [
        ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of an accessible share on the server', 'C$']),
      OptString.new('RPATH', [true, 'The name of the remote file/directory relative to the share'])
    ], self.class)

  end

  def run_host(ip)

    vprint_status("Connecting to the server...")

    begin
    connect()
    smb_login()

    vprint_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
    self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    vprint_status("Checking for file/folder #{datastore['RPATH']}...")

    if (fd = simple.open("\\#{datastore['RPATH']}", 'o')) # mode is open only - do not create/append/write etc
      print_good("File FOUND: \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']}")
      fd.close
    end
    rescue ::Rex::HostUnreachable
      vprint_error("Host #{rhost} offline.")
    rescue ::Rex::Proto::SMB::Exceptions::LoginError
      vprint_error("Host #{rhost} login error.")
    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      if e.get_error(e.error_code) == "STATUS_FILE_IS_A_DIRECTORY"
        print_good("Directory FOUND: \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']}")
      elsif e.get_error(e.error_code) == "STATUS_OBJECT_NAME_NOT_FOUND"
        vprint_error("Object \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']} NOT found!")
      elsif e.get_error(e.error_code) == "STATUS_OBJECT_PATH_NOT_FOUND"
        vprint_error("Object PATH \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{datastore['RPATH']} NOT found!")
      elsif e.get_error(e.error_code) == "STATUS_ACCESS_DENIED"
        vprint_error("Host #{rhost} reports access denied.")
      elsif e.get_error(e.error_code) == "STATUS_BAD_NETWORK_NAME"
        vprint_error("Host #{rhost} is NOT connected to #{datastore['SMBDomain']}!")
      elsif e.get_error(e.error_code) == "STATUS_INSUFF_SERVER_RESOURCES"
        vprint_error("Host #{rhost} rejected with insufficient resources!")
      else
        raise e
      end
    end
  end

end
