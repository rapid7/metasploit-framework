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
  include Msf::OptionalSession::SMB

  def initialize
    super(
      'Name' => 'SMB File Upload Utility',
      'Description' => %(
        This module uploads a file to a target share and path. The only reason
      to use this module is if your existing SMB client is not able to support the features
      of the Metasploit Framework that you need, like pass-the-hash authentication.
      ),
      'Author' => [
        'hdm' # metasploit module
      ],
      'References' => [
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK],
        'Reliability' => []
      }
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$'])
    ])
  end

  def run_host(_ip)
    validate_lpaths!
    validate_rpaths!
    begin
      if session
        print_status("Using existing session #{session.sid}")
        self.simple = session.simple_client
      else
        vprint_status('Connecting to the server...')
        connect
        smb_login
      end

      vprint_status("Mounting the remote share \\\\#{simple.address}\\#{datastore['SMBSHARE']}'...")
      simple.connect("\\\\#{simple.address}\\#{datastore['SMBSHARE']}")

      remote_path = remote_paths.first

      if local_paths.nil?
        print_error('Local paths not specified')
        return
      end

      local_paths.each do |local_path|
        vprint_status("Trying to upload #{local_path} to #{remote_path}...")

        fd = simple.open(remote_path.to_s, 'wct', write: true)
        data = ::File.read(datastore['LPATH'], ::File.size(datastore['LPATH']), mode: 'rb')
        fd.write(data)
        fd.close

        print_good("#{local_path} uploaded to #{remote_path}")
      rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
        elog("Unable to upload #{local_path} to #{remote_path}", error: e)
        print_error("Unable to upload #{local_path} to #{remote_path} : #{e.message}")
      end
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      elog('Unable to login:', error: e)
      print_error("Unable to login: #{e.message}")
    end
  end
end
