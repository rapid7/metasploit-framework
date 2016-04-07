##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::SMB::Client::LocalPaths
  include Msf::Exploit::Remote::SMB::Client::RemotePaths
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
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$'])
    ], self.class)

  end

  def run_host(_ip)
    begin
      vprint_status("#{peer}: Connecting to the server...")
      connect()
      smb_login()

      vprint_status("#{peer}: Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
      self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

      remote_path = remote_paths.first
      local_paths.each do |local_path|
        begin
          vprint_status("#{peer}: Trying to upload #{local_path} to #{remote_path}...")

          fd = simple.open("\\#{remote_path}", 'rwct')
          data = ::File.read(datastore['LPATH'], ::File.size(datastore['LPATH']))
          fd.write(data)
          fd.close

          print_good("#{peer}: #{local_path} uploaded to #{remote_path}")
        rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
          elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
          print_error("#{peer} Unable to upload #{local_path} to #{remote_path} : #{e.message}")
        end
      end
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      print_error("#{peer} Unable to login: #{e.message}")
    end
  end
end
