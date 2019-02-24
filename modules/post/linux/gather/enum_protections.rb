##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super( update_info( info,
      'Name'          => 'Linux Gather Protection Enumeration',
      'Description'   => %q{
        This module tries to find certain installed applications that can be used
        to prevent, or detect our attacks, which is done by locating certain
        binary locations, and see if they are indeed executables.  For example,
        if we are able to run 'snort' as a command, we assume it's one of the files
        we are looking for.

        This module is meant to cover various antivirus, rootkits, IDS/IPS,
        firewalls, and other software.
      },
      'License'       => MSF_LICENSE,
      'Author'        => 'ohdae <bindshell[at]live.com>',
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  def run
    distro = get_sysinfo

    print_status "Running module against #{session.session_host} [#{get_hostname}]"
    print_status 'Info:'
    print_status "\t#{distro[:version]}"
    print_status "\t#{distro[:kernel]}"

    print_status 'Finding installed applications...'
    find_apps
  end

  def which(env_paths, cmd)
    env_paths.each do |path|
      cmd_path = "#{path}/#{cmd}"
      return cmd_path if file_exist? cmd_path
    end
    nil
  end

  def find_apps
    apps = %w(
      truecrypt bulldog ufw iptables logrotate logwatch
      chkrootkit clamav snort tiger firestarter avast lynis
      rkhunter tcpdump webmin jailkit pwgen proxychains bastille
      psad wireshark nagios apparmor honeyd thpot
      aa-status gradm2 getenforce tripwire
    )

    env_paths = get_path.split ':'

    apps.each do |app|
      next unless command_exists? app

      path = which env_paths, app
      next unless path

      print_good "#{app} found: #{path}"
      report_note(
        :host   => session,
        :type   => 'linux.protection',
        :data   => path,
        :update => :unique_data
      )
    end

    print_status 'Installed applications saved to notes.'
  end
end
