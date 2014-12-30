##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::Remote::SMB::Authenticated
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

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

  def peer
    "#{rhost}:#{rport}"
  end

  def setup
    @data = ::File.read(datastore['LPATH'], ::File.size(datastore['LPATH']))
    vprint_status("#{peer}: Read #{@data.length} bytes from #{datastore['LPATH']}...")
  end

  def run_host(_ip)
    begin
      vprint_status("#{peer}: Connecting to the server...")
      connect()
      smb_login()

      vprint_status("#{peer}: Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
      self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

      vprint_status("#{peer}: Trying to upload #{datastore['RPATH']}...")

      fd = simple.open("\\#{datastore['RPATH']}", 'rwct')
      fd.write(@data)
      fd.close

      print_good("#{peer}: The file has been uploaded to #{datastore['RPATH']}...")
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      print_error("#{peer} Unable to login: #{e.message}")
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      print_error("#{peer} Unable to upload the file: #{e.message}")
    end
  end
end
