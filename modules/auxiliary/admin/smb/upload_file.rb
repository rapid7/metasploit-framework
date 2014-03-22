##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize
    super(
      'Name'        => 'SMB File Upload Utility',
      'Description' => %Q{
        This module uploads a file to a target share and path. The only reason
      to use this module is if your existing SMB client is not able to support the features
      of the Metasploit Framework that you need, like pass-the-hash authentication.
      },
      'Author'      =>
        [
          'hdm'    # metasploit module
        ],
      'References'  =>
        [
        ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
      OptString.new('RPATH', [true, 'The name of the remote file relative to the share']),
      OptString.new('LPATH', [true, 'The path of the local file to upload'])
    ], self.class)

  end

  def run

    data = ::File.read(datastore['LPATH'], ::File.size(datastore['LPATH']))
    print_status("Read #{data.length} bytes from #{datastore['LPATH']}...")

    print_status("Connecting to the server...")
    connect()
    smb_login()

    print_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
    self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    print_status("Trying to upload #{datastore['RPATH']}...")

    fd = simple.open("\\#{datastore['RPATH']}", 'rwct')
    fd.write(data)
    fd.close

    print_status("The file has been uploaded to #{datastore['RPATH']}...")
  end

end
