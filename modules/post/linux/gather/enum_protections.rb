##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info={})
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
      'Author'        =>
        [
          'ohdae <bindshell[at]live.com>'
        ],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ 'shell' ]
    ))
  end

  def run
    distro = get_sysinfo
    h = get_host

    print_status("Running module against #{h}")
    print_status("Info:")
    print_status("\t#{distro[:version]}")
    print_status("\t#{distro[:kernel]}")

    print_status("Finding installed applications...")
    find_apps
  end

  def get_host
    case session.type
    when /meterpreter/
      host = sysinfo["Computer"]
    when /shell/
      host = session.shell_command_token("hostname").chomp
    end

    return host
  end

  def which(env_paths, cmd)
    for path in env_paths
      if "#{cmd}" == cmd_exec("/bin/ls #{path} | /bin/grep '#{cmd}'")
        return "#{path}/#{cmd}"
      end
    end
    return nil
  end

  def find_apps
    apps = [
      "truecrypt", "bulldog", "ufw", "iptables", "logrotate", "logwatch",
      "chkrootkit", "clamav", "snort", "tiger", "firestarter", "avast", "lynis",
      "rkhunter", "tcpdump", "webmin", "jailkit", "pwgen", "proxychains", "bastille",
      "psad", "wireshark", "nagios", "nagios", "apparmor", "honeyd", "thpot"
    ]

    env_paths = cmd_exec("echo $PATH").split(":")

    apps.each do |a|
      output = which(env_paths, a)
      if output
        print_good("#{a} found: #{output}")

        report_note(
          :host_name => get_host,
          :type      => "linux.protection",
          :data      => output,
          :update    => :unique_data
        )
      end
    end

    print_status("Installed applications saved to notes.")
  end
end
