##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::SMB::Authenticated
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize
    super(
      'Name'        => 'SMB File Delete Utility',
      'Description' => %Q{
        This module deletes a file from a target share and path. The only reason
      to use this module is if your existing SMB client is not able to support the features
      of the Metasploit Framework that you need, like pass-the-hash authentication.
      },
      'Author'      =>
        [
          'mubix' # copied from hdm upload_file module
        ],
      'References'  =>
        [
        ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a share on the RHOST', 'C$']),
      OptString.new('RPATH', [true, 'The name of the remote file relative to the share'])
    ], self.class)
  end

  def smb_delete_file
    print_status("Connecting to the server...")
    connect()
    smb_login()

    print_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
    self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    simple.delete("\\#{datastore['RPATH']}")

    # If there's no exception raised at this point, we assume the file has been removed.
    print_status("File deleted: #{datastore['RPATH']}...")
  end

  def run
    begin
      smb_delete_file
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      print_error("Unable to login: #{e.message}")
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      print_error("Cannot delete the file: #{e.message}")
    end
  end

end
