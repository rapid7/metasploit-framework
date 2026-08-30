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
        'Name' => 'Solaris Gather Configured Services',
        'Description' => %q{
          Post module to enumerate services on a Solaris system.
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
    store_loot('solaris.version', 'text/plain', session, "Distro: #{distro[:hostname]}, Version: #{distro[:version]}, Kernel: #{distro[:kernel]}", 'solaris_info.txt', 'Solaris Version')

    print_good('Info:')
    print_good("\t#{distro[:version]}")
    print_good("\t#{distro[:kernel]}")

    installed_pkg = get_services
    if installed_pkg.blank?
      print_error('No services identified')
      return
    end

    pkg_loot = store_loot('solaris.services', 'text/plain', session, installed_pkg, 'configured_services.txt', 'Solaris Configured Services')
    print_good("Service list saved to loot file: #{pkg_loot}")

    if datastore['VERBOSE']
      print_good('Services:')
      installed_pkg.each_line do |p|
        print_good("\t#{p.chomp}")
      end
    end
  end

  def get_services
    cmd_exec('/usr/bin/svcs -a') || ''
  end
end
