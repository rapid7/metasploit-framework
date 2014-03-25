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
      'Name'        => 'SMB File Download Utility',
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
      OptString.new('SMBSHARE', [true, 'The name of a share on the RHOST', 'C$']),
      OptString.new('RPATH', [true, 'The name of the remote file relative to the share'])
    ], self.class)

  end

  def smb_download
    print_status("Connecting to the #{rhost}:#{rport}...")
    connect()
    smb_login()

    print_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
    self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    print_status("Trying to download #{datastore['RPATH']}...")

    data = ''
    fd = simple.open("\\#{datastore['RPATH']}", 'ro')
    begin
      data = fd.read
    ensure
      fd.close
    end

    fname = datastore['RPATH'].split("\\")[-1]
    path = store_loot("smb.shares.file", "application/octet-stream", rhost, data, fname)
    print_good("#{fname} saved as: #{path}")
  end

  def run
    begin
      smb_download
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      print_error("Unable to login: #{e.message}")
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      print_error("Unable to download the file: #{e.message}")
    end
  end

end
