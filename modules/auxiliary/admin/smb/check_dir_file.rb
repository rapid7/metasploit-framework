##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
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
          'aushack',
          'j0hn__f'
        ],
      'References'  =>
        [
        ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of an accessible share on the server', 'C$']),
      OptString.new('RPATH', [true, 'The name of the remote file/directory relative to the share'])
    ])

  end

  def check_path(path)
    begin
      if (fd = simple.open("\\#{path}", 'o')) # mode is open only - do not create/append/write etc
        print_good("File FOUND: \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{path}")
        fd.close
      end
    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      case e.get_error(e.error_code)
      when "STATUS_FILE_IS_A_DIRECTORY"
        print_good("Directory FOUND: \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{path}")
      when "STATUS_OBJECT_NAME_NOT_FOUND"
        vprint_error("Object \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{path} NOT found!")
      when "STATUS_OBJECT_PATH_NOT_FOUND"
        vprint_error("Object PATH \\\\#{rhost}\\#{datastore['SMBSHARE']}\\#{path} NOT found!")
      when "STATUS_ACCESS_DENIED"
        vprint_error("Host reports access denied.")
      when "STATUS_BAD_NETWORK_NAME"
        vprint_error("Host is NOT connected to #{datastore['SMBDomain']}!")
      when "STATUS_INSUFF_SERVER_RESOURCES"
        vprint_error("Host rejected with insufficient resources!")
      when "STATUS_OBJECT_NAME_INVALID"
        vprint_error("opeining \\#{path} bad filename")
      else
        raise e
      end
    end
  end

  def run_host(ip)
    vprint_status("Connecting to the server...")

    begin
      connect
      smb_login

      vprint_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
      self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")
      vprint_status("Checking for file/folder #{datastore['RPATH']}...")

      datastore['RPATH'].each_line do |path|
        check_path(path.chomp)
      end #end do
    rescue ::Rex::HostUnreachable
      vprint_error("Host offline.")
    rescue ::Rex::Proto::SMB::Exceptions::LoginError
      print_error("Host login error.")
    rescue ::Rex::ConnectionRefused
      print_error "Unable to connect - connection refused"
    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
      print_error "Unable to connect to share #{datastore['SMBSHARE']}"
    end # end begin
  end # end def
end
