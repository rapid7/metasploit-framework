##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Solaris::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Solaris Gather Installed Packages',
        'Description' => %q{
          Post module to enumerate installed packages on a Solaris system.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'solaris' ],
        'SessionTypes' => [ 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    distro = get_sysinfo
    print_status("Running module against #{distro[:hostname]}")
    packages = cmd_exec('/usr/bin/pkginfo -l')

    if packages.blank?
      print_error('No packages identified')
      return
    end

    pkg_loot = store_loot('solaris.packages', 'text/plain', session, packages, 'installed_packages.txt', 'Solaris Installed Packages')
    print_good("Package list saved to loot file: #{pkg_loot}")

    if datastore['VERBOSE']
      packages.each do |p|
        print_good("\t#{p.chomp}")
      end
    end
  end
end
