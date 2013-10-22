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
        This module downloads a file from a target share and path. The only reason
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
      OptString.new('SMBSHARE', [true, 'The name of a share on the RHOST', 'C$']),
      OptString.new('RPATH', [true, 'The name of the remote file relative to the share']),
      OptString.new('LPATH', [false, 'The path of the local file to upload'])
    ], self.class)

  end

  def run

    print_status("Connecting to the server...")
    connect()
    smb_login()

    print_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
    self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    print_status("Trying to download #{datastore['RPATH']}...")

    fd = simple.open("\\#{datastore['RPATH']}", 'ro')
    lfile = fd.read
    fd.close
    
    if datastore['LPATH']
      File.open("#{datastore['LPATH']}", 'w') {|f| f.write(lfile) }
      print_status("The file has been downloaded to #{datastore['LPATH']}...")
    else
      rfilename = datastore['RPATH'].split("\\")[-1]
      print_status(rfilename)
      File.open(rfilename, 'w') {|f| f.write(lfile) }
      print_status("LPATH not set, the file has been downloaded to #{rfilename}...")      
    end
  end

end
