##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  include Msf::Exploit::Remote::SMB::Client::RemotePaths
=======
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
<<<<<<< HEAD
<<<<<<< HEAD
  include Msf::Exploit::Remote::SMB::Client::RemotePaths
=======
=======
<<<<<<< HEAD
  include Msf::Exploit::Remote::SMB::Client::RemotePaths
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  include Msf::Exploit::Remote::SMB::Client::RemotePaths
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/pod/metasploit-framework
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
>>>>>>> origin/pod/metasploit-framework
=======
  include Msf::Exploit::Remote::SMB::Client::RemotePaths
>>>>>>> origin/pod/metasploit-serialized_class_loader
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize
    super(
      'Name'        => 'SMB File Download Utility',
      'Description' => %Q{
        This module downloads a file from a target share and path. The usual reason
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
    ], self.class)
<<<<<<< HEAD
=======
  end

  def peer
    "#{rhost}:#{rport}"
>>>>>>> origin/pod/metasploit-serialized_class_loader
  end

  def smb_download
    vprint_status("#{peer}: Connecting...")
    connect()
    smb_login()

    vprint_status("#{peer}: Mounting the remote share \\\\#{rhost}\\#{datastore['SMBSHARE']}'...")
    self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

    remote_paths.each do |remote_path|
      begin
        vprint_status("#{peer}: Trying to download #{remote_path}...")

        data = ''
        fd = simple.open("\\#{remote_path}", 'ro')
        begin
          data = fd.read
        ensure
          fd.close
        end

        fname = remote_path.split("\\")[-1]
        path = store_loot("smb.shares.file", "application/octet-stream", rhost, data, fname)
        print_good("#{peer}: #{remote_path} saved as: #{path}")
      rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
        elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
        print_error("#{peer} Unable to download #{remote_path}: #{e.message}")
      end
    end
  end

  def run_host(ip)
    begin
      smb_download
    rescue Rex::Proto::SMB::Exceptions::LoginError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      print_error("#{peer} Unable to login: #{e.message}")
    end
  end

end
