##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::SMB::Client::LocalPaths
  include Msf::Exploit::Remote::SMB::Client::RemotePaths
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

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
    ])

  end

  def run_host(_ip)
    begin
      vprint_status("Connecting to the server...")
      connect(versions: [1, 2])
      smb_login()

      vprint_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
      self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

      remote_path = remote_paths.first

      if local_paths.nil?
        print_error("Local paths not specified")
        return
      end

      local_paths.each do |local_path|
        begin
          vprint_status("Trying to upload #{local_path} to #{remote_path}...")

          fd = simple.open("#{remote_path}", 's', write: true)
          data = ::File.read(datastore['LPATH'], ::File.size(datastore['LPATH']))
          fd.write(data)
          fd.close

          print_good("#{local_path} uploaded to #{remote_path}")
        rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
          elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
          print_error("Unable to upload #{local_path} to #{remote_path} : #{e.message}")
        end
      end
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      print_error("Unable to login: #{e.message}")
    end
  end
end
