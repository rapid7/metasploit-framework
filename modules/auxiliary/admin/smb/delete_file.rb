##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::SMB::Client::RemotePaths
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize
    super(
      'Name'        => 'SMB File Delete Utility',
      'Description' => %Q{
        This module deletes a file from a target share and path. The usual reason
      to use this module is to work around limitations in an existing SMB client that may not
      be able to take advantage of pass-the-hash style authentication.
      },
      'Author'      =>
        [
          'mubix' # copied from hdm upload_file module
        ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a share on the RHOST', 'C$'])
    ])
  end

  def smb_delete_files
    vprint_status("Connecting to the server...")
    connect()
    smb_login()

    vprint_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
    self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    remote_paths.each do |remote_path|
      begin
        simple.delete("\\#{remote_path}")

        # If there's no exception raised at this point, we assume the file has been removed.
        print_good("Deleted: #{remote_path}")
      rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
        elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
        print_error("Cannot delete #{remote_path}: #{e.message}")
      end
    end
  end

  def run_host(_ip)
    begin
      smb_delete_files
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      print_error("Unable to login: #{e.message}")
    end
  end
end
