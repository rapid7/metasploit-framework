##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Solaris::System


  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Solaris Gather Installed Packages',
        'Description'   => %q{ Post Module to enumerate installed packages on a Solaris System},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'solaris' ],
        'SessionTypes'  => [ 'shell' ]
      ))

  end

  # Run Method for when run command is issued
  def run
    distro = get_sysinfo
    print_status("Running Module against #{distro[:hostname]}")
    packages = cmd_exec("/usr/bin/pkginfo -l")
    pkg_loot = store_loot("solaris.packages", "text/plain", session, packages, "installed_packages.txt", "Solaris Installed Packages")
    print_good("Package list saved to loot file: #{pkg_loot}")

    if datastore['VERBOSE']
      packages.each do |p|
        print_good("\t#{p.chomp}")
      end
    end

  end
end
