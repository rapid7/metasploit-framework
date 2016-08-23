##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::System


  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Linux Gather Chroot Detection',
        'Description'   => %q{
          This module attemps to determine wheter the system is running
          inside a chroot jail
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Matheus <mmedeiros450[at]gmail.com>' ],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))
  end


  # Main method
  def run
    print_status("checking chroot ...")

  #checking if are in chroot, first check if /proc is mounted, and
  # after check broken symlinks for executables

    chroot = nil
    if not directory?("/proc/")
      chroot = "/proc/ not found"
    else
      dir("/proc/").each do |pid|
        pid = Integer(pid) rescue nil
        if pid
          filename = File.readlink("/proc/#{pid}/exe") rescue nil
          next if not filename

          stat = session.fs.file.stat(filename) rescue nil
          if not stat
            chroot = "broken link found #{filename}"
            break
          end
        end
      end
    end

    if not chroot
      print_status("chroot not detect")
    else
      print_good("this appears to be in chroot #{chroot}")
    end
  end

end
